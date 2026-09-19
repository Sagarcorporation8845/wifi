#include "capture_session.h"

#include <string.h>
#include <ctype.h>

#include "esp_err.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static capture_session_t current_session;
static SemaphoreHandle_t session_lock = NULL;
static uint32_t next_session_id = 1;

static bool lock_session(void) {
    return session_lock != NULL &&
           xSemaphoreTake(session_lock, portMAX_DELAY) == pdTRUE;
}

static void unlock_session(void) {
    xSemaphoreGive(session_lock);
}

static void copy_ssid(char *dst, const uint8_t *src) {
    size_t out = 0;

    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    for (size_t i = 0; i < 32 && out < 32; ++i) {
        unsigned char c = src[i];

        if (c == '\0') {
            break;
        }

        /*
         * Keep the session JSON deterministic and safe for malformed SSIDs.
         * Printable UTF-8 bytes are preserved only when they are ASCII; other
         * bytes are replaced because the embedded JSON API is ASCII-safe.
         */
        dst[out++] = (c >= 0x20 && c <= 0x7e) ? (char)c : '?';
    }

    dst[out] = '\0';
}

void capture_session_init(void) {
    session_lock = xSemaphoreCreateMutex();
    ESP_ERROR_CHECK(session_lock == NULL ? ESP_ERR_NO_MEM : ESP_OK);

    memset(&current_session, 0, sizeof(current_session));
    current_session.state = CAPTURE_SESSION_IDLE;
}

void capture_session_reset(void) {
    if (!lock_session()) {
        return;
    }

    memset(&current_session, 0, sizeof(current_session));
    current_session.state = CAPTURE_SESSION_IDLE;

    unlock_session();
}

void capture_session_start(const wifi_ap_record_t *ap_record,
                           uint8_t ap_record_id,
                           uint8_t type,
                           uint8_t method,
                           uint8_t timeout_sec) {
    if (ap_record == NULL || !lock_session()) {
        return;
    }

    memset(&current_session, 0, sizeof(current_session));

    current_session.id = next_session_id++;
    if (next_session_id == 0) {
        next_session_id = 1;
    }

    current_session.type = type;
    current_session.method = method;
    current_session.timeout_sec = timeout_sec;
    current_session.ap_record_id = ap_record_id;
    current_session.channel = ap_record->primary;
    current_session.rssi = ap_record->rssi;

    memcpy(current_session.bssid, ap_record->bssid, sizeof(current_session.bssid));
    copy_ssid(current_session.ssid, ap_record->ssid);

    current_session.state = CAPTURE_SESSION_RUNNING;
    current_session.started_at_ms = (uint32_t)(esp_timer_get_time() / 1000ULL);

    unlock_session();
}

void capture_session_record_eapol(unsigned frame_len,
                                  bool hccapx_ready,
                                  uint32_t pcap_size) {
    if (!lock_session()) {
        return;
    }

    if (current_session.state == CAPTURE_SESSION_RUNNING) {
        current_session.frames_seen++;
        current_session.eapol_frames++;
        current_session.last_frame_len = frame_len > UINT16_MAX
            ? UINT16_MAX
            : (uint16_t)frame_len;
        current_session.hccapx_ready = hccapx_ready;
        current_session.pcap_size = pcap_size;
    }

    unlock_session();
}

void capture_session_record_pmkid(unsigned count) {
    if (!lock_session()) {
        return;
    }

    if (current_session.state == CAPTURE_SESSION_RUNNING) {
        if (count > UINT16_MAX) {
            current_session.pmkid_count = UINT16_MAX;
        } else {
            current_session.pmkid_count = (uint16_t)count;
        }
    }

    unlock_session();
}

void capture_session_set_result(uint16_t result_size, bool hccapx_ready) {
    if (!lock_session()) {
        return;
    }

    current_session.result_size = result_size;
    current_session.hccapx_ready = hccapx_ready;

    unlock_session();
}

void capture_session_finish(capture_session_state_t state) {
    if (!lock_session()) {
        return;
    }

    current_session.state = state;

    if (current_session.started_at_ms != 0) {
        uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000ULL);
        current_session.elapsed_ms = now_ms - current_session.started_at_ms;
    }

    unlock_session();
}

bool capture_session_get(capture_session_t *session) {
    if (session == NULL || !lock_session()) {
        return false;
    }

    *session = current_session;

    if (current_session.state == CAPTURE_SESSION_RUNNING &&
        current_session.started_at_ms != 0) {
        uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000ULL);
        session->elapsed_ms = now_ms - current_session.started_at_ms;
    }

    unlock_session();
    return true;
}
