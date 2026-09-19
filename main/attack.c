#include "attack.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_timer.h"

#include "attack_pmkid.h"
#include "attack_handshake.h"
#include "attack_dos.h"
#include "capture_session.h"
#include "webserver.h"
#include "wifi_controller.h"

static const char *TAG = "attack";
static attack_status_t attack_status = {
    .state = READY,
    .type = 0xff,
    .content_size = 0,
    .content = NULL
};
static esp_timer_handle_t attack_timeout_handle;

static void attack_cancel_timeout(void) {
    esp_err_t result = esp_timer_stop(attack_timeout_handle);

    if (result != ESP_OK && result != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "Failed to stop attack timeout timer: %s",
                 esp_err_to_name(result));
    }
}

static void attack_stop_active(void) {
    switch (attack_status.type) {
        case ATTACK_TYPE_PMKID:
            attack_pmkid_stop();
            break;

        case ATTACK_TYPE_HANDSHAKE:
            attack_handshake_stop();
            break;

        case ATTACK_TYPE_DOS:
            attack_dos_stop();
            break;

        default:
            break;
    }
}

const attack_status_t *attack_get_status() {
    return &attack_status;
}

void attack_update_status(attack_state_t state) {
    attack_status.state = state;

    if (state == FINISHED || state == FAILED) {
        attack_cancel_timeout();
    }
}

void attack_append_status_content(uint8_t *buffer, unsigned size) {
    if (buffer == NULL || size == 0) {
        ESP_LOGE(TAG, "Invalid status content append request");
        return;
    }

    /*
     * The binary status endpoint is a legacy compatibility path. Keep a
     * bounded result buffer so a malformed or unexpectedly long capture cannot
     * exhaust the ESP32 heap.
     */
    const unsigned max_size = UINT16_MAX;
    if (attack_status.content_size >= max_size) {
        return;
    }

    unsigned available = max_size - attack_status.content_size;
    unsigned append_size = size > available ? available : size;

    char *reallocated_content =
        realloc(attack_status.content, attack_status.content_size + append_size);

    if (reallocated_content == NULL) {
        ESP_LOGE(TAG, "Error reallocating status content");
        return;
    }

    memcpy(&reallocated_content[attack_status.content_size],
           buffer,
           append_size);

    attack_status.content = reallocated_content;
    attack_status.content_size += append_size;
}

char *attack_alloc_result_content(unsigned size) {
    if (attack_status.content != NULL) {
        free(attack_status.content);
        attack_status.content = NULL;
    }

    attack_status.content_size = 0;

    if (size == 0 || size > UINT16_MAX) {
        ESP_LOGE(TAG, "Invalid result content size: %u", size);
        return NULL;
    }

    attack_status.content = (char *)malloc(size);
    if (attack_status.content == NULL) {
        ESP_LOGE(TAG, "Unable to allocate %u bytes for result", size);
        return NULL;
    }

    attack_status.content_size = (uint16_t)size;
    return attack_status.content;
}

static void attack_timeout(void *arg) {
    ESP_LOGD(TAG, "Attack timed out");

    attack_stop_active();
    attack_status.state = TIMEOUT;
    capture_session_finish(CAPTURE_SESSION_TIMEOUT);
}

static esp_err_t validate_attack_request(const attack_request_t *request) {
    if (request == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (request->type > ATTACK_TYPE_DOS) {
        return ESP_ERR_INVALID_ARG;
    }

    if (request->timeout == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    switch (request->type) {
        case ATTACK_TYPE_HANDSHAKE:
            if (request->method >= 3) {
                return ESP_ERR_INVALID_ARG;
            }
            break;

        case ATTACK_TYPE_DOS:
            if (request->method >= 3) {
                return ESP_ERR_INVALID_ARG;
            }
            break;

        case ATTACK_TYPE_PMKID:
            /*
             * PMKID does not use an attack method. The value is ignored for
             * compatibility with the fixed request structure.
             */
            break;

        case ATTACK_TYPE_PASSIVE:
            break;

        default:
            return ESP_ERR_INVALID_ARG;
    }

    return ESP_OK;
}

static void attack_request_handler(void *args, esp_event_base_t event_base,
                                   int32_t event_id, void *event_data) {
    if (event_data == NULL) {
        return;
    }

    if (attack_status.state == RUNNING) {
        ESP_LOGW(TAG, "Attack request rejected while another operation is running");
        return;
    }

    attack_request_t *attack_request = (attack_request_t *)event_data;

    if (validate_attack_request(attack_request) != ESP_OK) {
        ESP_LOGE(TAG, "Invalid attack request");
        attack_status.state = FAILED;
        capture_session_finish(CAPTURE_SESSION_FAILED);
        return;
    }

    const wifi_ap_record_t *ap_record =
        wifictl_get_ap_record(attack_request->ap_record_id);

    if (ap_record == NULL) {
        ESP_LOGE(TAG, "Requested AP record is no longer available");
        attack_status.state = FAILED;
        capture_session_finish(CAPTURE_SESSION_FAILED);
        return;
    }

    if (attack_status.content != NULL) {
        free(attack_status.content);
        attack_status.content = NULL;
    }
    attack_status.content_size = 0;

    attack_status.state = RUNNING;
    attack_status.type = attack_request->type;

    capture_session_start(
        ap_record,
        attack_request->ap_record_id,
        attack_request->type,
        attack_request->method,
        attack_request->timeout);

    esp_err_t timer_result = esp_timer_start_once(
        attack_timeout_handle,
        (uint64_t)attack_request->timeout * 1000000ULL);

    if (timer_result != ESP_OK) {
        ESP_LOGE(TAG, "Unable to start attack timer: %s",
                 esp_err_to_name(timer_result));
        attack_status.state = FAILED;
        capture_session_finish(CAPTURE_SESSION_FAILED);
        return;
    }

    attack_config_t attack_config = {
        .type = attack_request->type,
        .method = attack_request->method,
        .timeout = attack_request->timeout,
        .ap_record = ap_record
    };

    switch (attack_config.type) {
        case ATTACK_TYPE_PMKID:
            attack_pmkid_start(&attack_config);
            break;

        case ATTACK_TYPE_HANDSHAKE:
            attack_handshake_start(&attack_config);
            break;

        case ATTACK_TYPE_PASSIVE:
            /*
             * Preserve the legacy passive type but route it through the same
             * passive handshake collector used by the handshake feature.
             */
            attack_config.method = ATTACK_HANDSHAKE_METHOD_PASSIVE;
            attack_handshake_start(&attack_config);
            break;

        case ATTACK_TYPE_DOS:
            attack_dos_start(&attack_config);
            break;

        default:
            attack_status.state = FAILED;
            capture_session_finish(CAPTURE_SESSION_FAILED);
            attack_cancel_timeout();
            break;
    }
}

static void attack_reset_handler(void *args, esp_event_base_t event_base,
                                 int32_t event_id, void *event_data) {
    ESP_LOGD(TAG, "Resetting attack status...");

    if (attack_status.state == RUNNING) {
        attack_stop_active();
        attack_cancel_timeout();
    }

    if (attack_status.content != NULL) {
        free(attack_status.content);
        attack_status.content = NULL;
    }

    attack_status.content_size = 0;
    attack_status.type = 0xff;
    attack_status.state = READY;

    capture_session_reset();
}

void attack_init() {
    const esp_timer_create_args_t attack_timeout_args = {
        .callback = &attack_timeout
    };

    ESP_ERROR_CHECK(
        esp_timer_create(&attack_timeout_args, &attack_timeout_handle));

    ESP_ERROR_CHECK(esp_event_handler_register(
        WEBSERVER_EVENTS,
        WEBSERVER_EVENT_ATTACK_REQUEST,
        &attack_request_handler,
        NULL));

    ESP_ERROR_CHECK(esp_event_handler_register(
        WEBSERVER_EVENTS,
        WEBSERVER_EVENT_ATTACK_RESET,
        &attack_reset_handler,
        NULL));
}
