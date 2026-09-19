#include "frame_analyzer.h"

#include <stdint.h>
#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"

#include "wifi_controller.h"
#include "frame_analyzer_parser.h"

static const char *TAG = "frame_analyzer";
static uint8_t target_bssid[6];
static search_type_t search_type = -1;

static void data_frame_handler(void *args, esp_event_base_t event_base,
                               int32_t event_id, void *event_data) {
    ESP_LOGV(TAG, "Handling DATA frame");

    if (event_data == NULL) {
        return;
    }

    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *)event_data;
    const size_t frame_len = frame->rx_ctrl.sig_len;

    if (!is_frame_bssid_matching(frame, frame_len, target_bssid)) {
        ESP_LOGV(TAG, "Not matching BSSIDs.");
        return;
    }

    eapol_packet_t *eapol_packet =
        parse_eapol_packet((data_frame_t *)frame->payload, frame_len);

    if (eapol_packet == NULL) {
        ESP_LOGV(TAG, "Not an EAPOL packet.");
        return;
    }

    uint8_t *frame_end = frame->payload + frame_len;
    uint8_t *eapol_start = (uint8_t *)eapol_packet;

    if (eapol_start >= frame_end) {
        return;
    }

    eapol_key_packet_t *eapol_key_packet =
        parse_eapol_key_packet(
            eapol_packet,
            (size_t)(frame_end - eapol_start));

    if (eapol_key_packet == NULL) {
        ESP_LOGV(TAG, "Not an EAPOL-Key packet");
        return;
    }

    if (search_type == SEARCH_HANDSHAKE) {
        ESP_ERROR_CHECK_WITHOUT_ABORT(esp_event_post(
            FRAME_ANALYZER_EVENTS,
            DATA_FRAME_EVENT_EAPOLKEY_FRAME,
            frame,
            sizeof(wifi_promiscuous_pkt_t) + frame_len,
            portMAX_DELAY));
        return;
    }

    if (search_type == SEARCH_PMKID) {
        pmkid_item_t *pmkid_items = parse_pmkid(eapol_key_packet);
        if (pmkid_items == NULL) {
            return;
        }

        ESP_ERROR_CHECK(esp_event_post(
            FRAME_ANALYZER_EVENTS,
            DATA_FRAME_EVENT_PMKID,
            &pmkid_items,
            sizeof(pmkid_item_t *),
            portMAX_DELAY));
    }
}

void frame_analyzer_capture_start(search_type_t search_type_arg,
                                  const uint8_t *bssid) {
    if (bssid == NULL) {
        ESP_LOGE(TAG, "Cannot start analysis without a BSSID");
        return;
    }

    ESP_LOGI(TAG, "Frame analysis started...");
    search_type = search_type_arg;
    memcpy(target_bssid, bssid, sizeof(target_bssid));

    ESP_ERROR_CHECK(esp_event_handler_register(
        SNIFFER_EVENTS,
        SNIFFER_EVENT_CAPTURED_DATA,
        &data_frame_handler,
        NULL));
}

void frame_analyzer_capture_stop() {
    ESP_ERROR_CHECK(esp_event_handler_unregister(
        SNIFFER_EVENTS,
        SNIFFER_EVENT_CAPTURED_DATA,
        &data_frame_handler));

    search_type = -1;
    memset(target_bssid, 0, sizeof(target_bssid));
}
