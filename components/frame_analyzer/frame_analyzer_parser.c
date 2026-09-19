#include "frame_analyzer_parser.h"

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "arpa/inet.h"

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"

static const char *TAG = "frame_analyzer:parser";

ESP_EVENT_DEFINE_BASE(FRAME_ANALYZER_EVENTS);

void print_raw_frame(const wifi_promiscuous_pkt_t *frame) {
    if (frame == NULL) {
        return;
    }

    for (unsigned i = 0; i < frame->rx_ctrl.sig_len; i++) {
        printf("%02x", frame->payload[i]);
    }
    printf("\n");
}

void print_mac_address(const uint8_t *a) {
    if (a == NULL) {
        return;
    }

    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           a[0], a[1], a[2], a[3], a[4], a[5]);
    printf("\n");
}

bool is_frame_bssid_matching(const wifi_promiscuous_pkt_t *frame,
                             size_t frame_len,
                             const uint8_t *bssid) {
    if (frame == NULL || bssid == NULL ||
        frame_len < sizeof(data_frame_mac_header_t)) {
        return false;
    }

    const data_frame_mac_header_t *mac_header =
        (const data_frame_mac_header_t *)frame->payload;

    return memcmp(mac_header->addr3, bssid, 6) == 0;
}

eapol_packet_t *parse_eapol_packet(data_frame_t *frame, size_t frame_len) {
    if (frame == NULL || frame_len < sizeof(data_frame_mac_header_t)) {
        return NULL;
    }

    if (frame->mac_header.frame_control.protected_frame == 1) {
        ESP_LOGV(TAG, "Protected frame, skipping...");
        return NULL;
    }

    size_t frame_buffer_offset = sizeof(data_frame_mac_header_t);

    if (frame->mac_header.frame_control.subtype > 7) {
        frame_buffer_offset += 2;
    }

    const size_t required_prefix =
        frame_buffer_offset + sizeof(llc_snap_header_t) +
        sizeof(uint16_t) + sizeof(eapol_packet_header_t);

    if (frame_len < required_prefix) {
        ESP_LOGV(TAG, "Frame too short for EAPOL parsing");
        return NULL;
    }

    uint8_t *frame_buffer = frame->body;
    frame_buffer += frame_buffer_offset - sizeof(data_frame_mac_header_t);
    frame_buffer += sizeof(llc_snap_header_t);

    uint16_t ether_type;
    memcpy(&ether_type, frame_buffer, sizeof(ether_type));

    if (ntohs(ether_type) != ETHER_TYPE_EAPOL) {
        return NULL;
    }

    frame_buffer += sizeof(ether_type);
    eapol_packet_t *eapol_packet = (eapol_packet_t *)frame_buffer;

    const uint16_t body_len = ntohs(eapol_packet->header.packet_body_length);
    const size_t eapol_header_offset =
        frame_buffer_offset + sizeof(llc_snap_header_t) + sizeof(ether_type);
    const size_t available_eapol_len = frame_len - eapol_header_offset;

    if (body_len > available_eapol_len - sizeof(eapol_packet_header_t)) {
        ESP_LOGV(TAG, "Truncated EAPOL packet");
        return NULL;
    }

    ESP_LOGD(TAG, "EAPOL packet");
    return eapol_packet;
}

eapol_key_packet_t *parse_eapol_key_packet(eapol_packet_t *eapol_packet,
                                           size_t eapol_frame_len) {
    if (eapol_packet == NULL ||
        eapol_frame_len < sizeof(eapol_packet_header_t)) {
        return NULL;
    }

    if (eapol_packet->header.packet_type != EAPOL_KEY) {
        ESP_LOGD(TAG, "Not an EAPOL-Key packet.");
        return NULL;
    }

    const uint16_t body_len = ntohs(eapol_packet->header.packet_body_length);

    if (body_len > eapol_frame_len - sizeof(eapol_packet_header_t) ||
        body_len < offsetof(eapol_key_packet_t, key_data)) {
        ESP_LOGV(TAG, "Truncated EAPOL-Key packet");
        return NULL;
    }

    eapol_key_packet_t *eapol_key_packet =
        (eapol_key_packet_t *)eapol_packet->packet_body;

    const uint16_t key_data_len = ntohs(eapol_key_packet->key_data_length);
    const size_t fixed_key_body_len = offsetof(eapol_key_packet_t, key_data);

    if (key_data_len > body_len - fixed_key_body_len) {
        ESP_LOGV(TAG, "Truncated EAPOL-Key key data");
        return NULL;
    }

    return eapol_key_packet;
}

static pmkid_item_t *parse_pmkid_from_key_data(uint8_t *key_data,
                                                uint16_t length) {
    uint8_t *index = key_data;
    size_t remaining = length;
    pmkid_item_t *head = NULL;

    while (remaining >= 2) {
        const uint8_t element_id = index[0];
        const uint8_t element_len = index[1];

        if ((size_t)element_len > remaining - 2) {
            ESP_LOGV(TAG, "Malformed key-data element length");
            break;
        }

        /*
         * RSN PMKID KDE:
         *   Element ID 0xdd
         *   Length     >=20
         *   OUI        00:0f:ac
         *   Data type  04
         *   PMKID      first 16 bytes of KDE payload
         */
        if (element_id == KEY_DATA_TYPE &&
            element_len >= 20 &&
            index[2] == 0x00 &&
            index[3] == 0x0f &&
            index[4] == 0xac &&
            index[5] == KEY_DATA_DATA_TYPE_PMKID_KDE) {

            pmkid_item_t *item =
                (pmkid_item_t *)malloc(sizeof(pmkid_item_t));
            if (item == NULL) {
                ESP_LOGE(TAG, "Out of memory while parsing PMKID");
                break;
            }

            memcpy(item->pmkid, &index[6], 16);
            item->next = head;
            head = item;
        }

        index += 2 + element_len;
        remaining -= 2 + element_len;
    }

    return head;
}

pmkid_item_t *parse_pmkid(eapol_key_packet_t *eapol_key) {
    if (eapol_key == NULL) {
        return NULL;
    }

    const uint16_t key_data_len = ntohs(eapol_key->key_data_length);

    if (key_data_len == 0) {
        ESP_LOGD(TAG, "Empty Key Data");
        return NULL;
    }

    if (eapol_key->key_information.encrypted_key_data == 1) {
        ESP_LOGD(TAG, "Key Data encrypted");
        return NULL;
    }

    return parse_pmkid_from_key_data(eapol_key->key_data, key_data_len);
}
