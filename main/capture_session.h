#ifndef CAPTURE_SESSION_H
#define CAPTURE_SESSION_H

#include <stdbool.h>
#include <stdint.h>

#include "esp_wifi_types.h"

typedef enum {
    CAPTURE_SESSION_IDLE = 0,
    CAPTURE_SESSION_RUNNING,
    CAPTURE_SESSION_COMPLETE,
    CAPTURE_SESSION_TIMEOUT,
    CAPTURE_SESSION_FAILED
} capture_session_state_t;

typedef struct {
    uint32_t id;
    uint8_t type;
    uint8_t method;
    uint8_t timeout_sec;
    uint8_t ap_record_id;
    uint8_t channel;
    uint8_t bssid[6];
    char ssid[33];
    int8_t rssi;

    capture_session_state_t state;

    uint32_t frames_seen;
    uint32_t eapol_frames;
    uint16_t pmkid_count;
    uint16_t last_frame_len;

    uint32_t started_at_ms;
    uint32_t elapsed_ms;
    uint32_t pcap_size;

    uint16_t result_size;
    bool hccapx_ready;
} capture_session_t;

void capture_session_init(void);
void capture_session_reset(void);

void capture_session_start(const wifi_ap_record_t *ap_record,
                           uint8_t ap_record_id,
                           uint8_t type,
                           uint8_t method,
                           uint8_t timeout_sec);

void capture_session_record_eapol(unsigned frame_len,
                                  bool hccapx_ready,
                                  uint32_t pcap_size);

void capture_session_record_pmkid(unsigned count);
void capture_session_set_result(uint16_t result_size, bool hccapx_ready);
void capture_session_finish(capture_session_state_t state);

bool capture_session_get(capture_session_t *session);

#endif
