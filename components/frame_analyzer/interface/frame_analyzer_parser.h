#ifndef FRAME_ANALYZER_PARSER_H
#define FRAME_ANALYZER_PARSER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_wifi_types.h"
#include "frame_analyzer_types.h"

bool is_frame_bssid_matching(const wifi_promiscuous_pkt_t *frame,
                             size_t frame_len,
                             const uint8_t *bssid);

eapol_packet_t *parse_eapol_packet(data_frame_t *frame, size_t frame_len);

eapol_key_packet_t *parse_eapol_key_packet(eapol_packet_t *eapol_packet,
                                           size_t eapol_frame_len);

pmkid_item_t *parse_pmkid(eapol_key_packet_t *eapol_key);

void print_raw_frame(const wifi_promiscuous_pkt_t *frame);
void print_mac_address(const uint8_t *a);

#endif
