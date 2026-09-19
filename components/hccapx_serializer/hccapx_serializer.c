#include "hccapx_serializer.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "arpa/inet.h"

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"

#include "frame_analyzer_parser.h"
#include "frame_analyzer_types.h"

#define HCCAPX_SIGNATURE 0x58504348
#define HCCAPX_VERSION 4
#define HCCAPX_KEYVER_WPA 1
#define HCCAPX_KEYVER_WPA2 2
#define HCCAPX_MAX_EAPOL_SIZE 256

static const char *TAG = "hccapx_serializer";

static hccapx_t hccapx;
static unsigned message_ap = 0;
static unsigned message_sta = 0;
static unsigned eapol_source = 0;

static bool is_array_zero(const uint8_t *array, unsigned size) {
    if (array == NULL) {
        return true;
    }

    for (unsigned i = 0; i < size; i++) {
        if (array[i] != 0) {
            return false;
        }
    }

    return true;
}

void hccapx_serializer_init(const uint8_t *ssid, unsigned size) {
    memset(&hccapx, 0, sizeof(hccapx));

    hccapx.signature = HCCAPX_SIGNATURE;
    hccapx.version = HCCAPX_VERSION;
    hccapx.message_pair = 255;
    hccapx.keyver = HCCAPX_KEYVER_WPA2;

    message_ap = 0;
    message_sta = 0;
    eapol_source = 0;

    if (ssid == NULL) {
        return;
    }

    if (size > sizeof(hccapx.essid)) {
        size = sizeof(hccapx.essid);
    }

    hccapx.essid_len = (uint8_t)size;
    memcpy(hccapx.essid, ssid, size);
}

hccapx_t *hccapx_serializer_get() {
    if (hccapx.message_pair == 255) {
        return NULL;
    }

    return &hccapx;
}

static unsigned save_eapol(const eapol_packet_t *eapol_packet,
                           const eapol_key_packet_t *eapol_key_packet) {
    if (eapol_packet == NULL || eapol_key_packet == NULL) {
        return 1;
    }

    const unsigned eapol_len =
        sizeof(eapol_packet_header_t) +
        ntohs(eapol_packet->header.packet_body_length);

    if (eapol_len > HCCAPX_MAX_EAPOL_SIZE) {
        ESP_LOGW(TAG, "EAPOL is too long (%u/%u)",
                 eapol_len, HCCAPX_MAX_EAPOL_SIZE);
        return 1;
    }

    hccapx.eapol_len = (uint16_t)eapol_len;
    memcpy(hccapx.eapol, eapol_packet, eapol_len);
    memcpy(hccapx.keymic, eapol_key_packet->key_mic,
           sizeof(hccapx.keymic));

    /*
     * HCCAPX represents the WPA/WPA2 key version differently from the
     * descriptor-version bitfield used on the wire. Descriptor version 1 is
     * the legacy WPA form; versions 2/3 use the WPA2-compatible serializer
     * representation.
     */
    hccapx.keyver =
        eapol_key_packet->key_information.key_descriptor_version == 1
            ? HCCAPX_KEYVER_WPA
            : HCCAPX_KEYVER_WPA2;

    const size_t mic_offset =
        sizeof(eapol_packet_header_t) +
        offsetof(eapol_key_packet_t, key_mic);

    if (mic_offset + sizeof(eapol_key_packet->key_mic) <= eapol_len) {
        memset(&hccapx.eapol[mic_offset], 0,
               sizeof(eapol_key_packet->key_mic));
    }

    return 0;
}

static void ap_message_m1(const eapol_key_packet_t *eapol_key_packet) {
    message_ap = 1;
    memcpy(hccapx.nonce_ap, eapol_key_packet->key_nonce,
           sizeof(hccapx.nonce_ap));
}

static void ap_message_m3(const eapol_packet_t *eapol_packet,
                          const eapol_key_packet_t *eapol_key_packet) {
    if (message_ap == 0) {
        memcpy(hccapx.nonce_ap, eapol_key_packet->key_nonce,
               sizeof(hccapx.nonce_ap));
    }

    message_ap = 3;

    if (eapol_source == 2) {
        hccapx.message_pair = 2;
        return;
    }

    if (save_eapol(eapol_packet, eapol_key_packet) != 0) {
        return;
    }

    eapol_source = 3;
    if (message_sta == 2) {
        hccapx.message_pair = 3;
    }
}

static void ap_message(data_frame_t *frame,
                       const eapol_packet_t *eapol_packet,
                       const eapol_key_packet_t *eapol_key_packet) {
    if ((!is_array_zero(hccapx.mac_sta, sizeof(hccapx.mac_sta))) &&
        memcmp(frame->mac_header.addr1, hccapx.mac_sta,
               sizeof(hccapx.mac_sta)) != 0) {
        ESP_LOGV(TAG, "Different STA");
        return;
    }

    if (message_ap == 0) {
        memcpy(hccapx.mac_ap, frame->mac_header.addr2,
               sizeof(hccapx.mac_ap));
    }

    if (is_array_zero(eapol_key_packet->key_mic,
                      sizeof(eapol_key_packet->key_mic))) {
        ap_message_m1(eapol_key_packet);
    } else {
        ap_message_m3(eapol_packet, eapol_key_packet);
    }
}

static void sta_message_m2(const eapol_packet_t *eapol_packet,
                           const eapol_key_packet_t *eapol_key_packet) {
    message_sta = 2;

    memcpy(hccapx.nonce_sta, eapol_key_packet->key_nonce,
           sizeof(hccapx.nonce_sta));

    if (save_eapol(eapol_packet, eapol_key_packet) != 0) {
        return;
    }

    eapol_source = 2;

    if (message_ap == 1) {
        hccapx.message_pair = 0;
    }
}

static void sta_message_m4(const eapol_packet_t *eapol_packet,
                           const eapol_key_packet_t *eapol_key_packet) {
    if ((message_sta == 2) && (eapol_source != 0)) {
        ESP_LOGV(TAG, "Already have M2");
        return;
    }

    if (message_ap == 0) {
        ESP_LOGV(TAG, "ANonce missing; waiting for an AP message");
        return;
    }

    if (eapol_source == 3) {
        hccapx.message_pair = 4;
        return;
    }

    if (save_eapol(eapol_packet, eapol_key_packet) != 0) {
        return;
    }

    eapol_source = 4;

    if (message_ap == 1) {
        hccapx.message_pair = 1;
    } else if (message_ap == 3) {
        hccapx.message_pair = 5;
    }
}

static void sta_message(data_frame_t *frame,
                        const eapol_packet_t *eapol_packet,
                        const eapol_key_packet_t *eapol_key_packet) {
    if (is_array_zero(hccapx.mac_sta, sizeof(hccapx.mac_sta))) {
        memcpy(hccapx.mac_sta, frame->mac_header.addr2,
               sizeof(hccapx.mac_sta));
    } else if (memcmp(frame->mac_header.addr2, hccapx.mac_sta,
                      sizeof(hccapx.mac_sta)) != 0) {
        ESP_LOGV(TAG, "Different STA");
        return;
    }

    if (!is_array_zero(eapol_key_packet->key_nonce,
                       sizeof(eapol_key_packet->key_nonce))) {
        sta_message_m2(eapol_packet, eapol_key_packet);
    } else {
        sta_message_m4(eapol_packet, eapol_key_packet);
    }
}

void hccapx_serializer_add_frame(data_frame_t *frame, size_t frame_len) {
    if (frame == NULL || frame_len < sizeof(data_frame_mac_header_t)) {
        return;
    }

    eapol_packet_t *eapol_packet =
        parse_eapol_packet(frame, frame_len);
    if (eapol_packet == NULL) {
        return;
    }

    uint8_t *frame_end = frame->body +
                         (frame_len - sizeof(data_frame_mac_header_t));
    uint8_t *eapol_start = (uint8_t *)eapol_packet;

    if (eapol_start >= frame_end) {
        return;
    }

    eapol_key_packet_t *eapol_key_packet =
        parse_eapol_key_packet(
            eapol_packet,
            (size_t)(frame_end - eapol_start));

    if (eapol_key_packet == NULL) {
        return;
    }

    if (memcmp(frame->mac_header.addr2, frame->mac_header.addr3, 6) == 0) {
        ap_message(frame, eapol_packet, eapol_key_packet);
    } else if (memcmp(frame->mac_header.addr1, frame->mac_header.addr3, 6) == 0) {
        sta_message(frame, eapol_packet, eapol_key_packet);
    }
}
