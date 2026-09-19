#include "webserver.h"

#include <stdio.h>
#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_wifi_types.h"

#include "attack.h"
#include "attack_dos.h"
#include "attack_handshake.h"
#include "capture_session.h"
#include "hccapx_serializer.h"
#include "pcap_serializer.h"
#include "wifi_controller.h"

#include "pages/page_index.h"

static const char *TAG = "webserver";
ESP_EVENT_DEFINE_BASE(WEBSERVER_EVENTS);

static const char *attack_type_name(uint8_t type) {
    switch (type) {
        case ATTACK_TYPE_PASSIVE: return "PASSIVE";
        case ATTACK_TYPE_HANDSHAKE: return "HANDSHAKE";
        case ATTACK_TYPE_PMKID: return "PMKID";
        case ATTACK_TYPE_DOS: return "DOS";
        default: return "UNKNOWN";
    }
}

static const char *handshake_method_name(uint8_t method) {
    switch (method) {
        case ATTACK_HANDSHAKE_METHOD_ROGUE_AP: return "ROGUE_AP";
        case ATTACK_HANDSHAKE_METHOD_BROADCAST: return "BROADCAST";
        case ATTACK_HANDSHAKE_METHOD_PASSIVE: return "PASSIVE";
        default: return "UNKNOWN";
    }
}

static const char *dos_method_name(uint8_t method) {
    switch (method) {
        case ATTACK_DOS_METHOD_ROGUE_AP: return "ROGUE_AP";
        case ATTACK_DOS_METHOD_BROADCAST: return "BROADCAST";
        case ATTACK_DOS_METHOD_COMBINE_ALL: return "COMBINED";
        default: return "UNKNOWN";
    }
}

static const char *method_name(uint8_t type, uint8_t method) {
    if (type == ATTACK_TYPE_HANDSHAKE ||
        type == ATTACK_TYPE_PASSIVE) {
        return handshake_method_name(method);
    }

    if (type == ATTACK_TYPE_DOS) {
        return dos_method_name(method);
    }

    return "N/A";
}

static const char *session_state_name(capture_session_state_t state) {
    switch (state) {
        case CAPTURE_SESSION_IDLE: return "IDLE";
        case CAPTURE_SESSION_RUNNING: return "RUNNING";
        case CAPTURE_SESSION_COMPLETE: return "COMPLETE";
        case CAPTURE_SESSION_TIMEOUT: return "TIMEOUT";
        case CAPTURE_SESSION_FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
}

static void format_mac(const uint8_t *mac, char *out, size_t out_size) {
    if (mac == NULL || out == NULL || out_size < 18) {
        if (out != NULL && out_size > 0) {
            out[0] = '\0';
        }
        return;
    }

    snprintf(out, out_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*
 * Encode scanned SSIDs as JSON-safe strings. We intentionally represent
 * non-ASCII bytes as \u00XX so malformed beacon data cannot corrupt JSON or
 * become HTML when consumed by the UI.
 */
static size_t json_escape_bytes(const uint8_t *src, size_t src_len,
                                char *dst, size_t dst_size) {
    if (dst == NULL || dst_size == 0) {
        return 0;
    }

    size_t out = 0;

    for (size_t i = 0; i < src_len && out + 1 < dst_size; ++i) {
        const uint8_t c = src[i];

        if (c == '"' || c == '\\') {
            if (out + 2 >= dst_size) {
                break;
            }
            dst[out++] = '\\';
            dst[out++] = (char)c;
        } else if (c == '\n' || c == '\r' || c == '\t') {
            if (out + 2 >= dst_size) {
                break;
            }
            dst[out++] = '\\';
            dst[out++] = c == '\n' ? 'n' : (c == '\r' ? 'r' : 't');
        } else if (c < 0x20 || c >= 0x7f) {
            if (out + 6 >= dst_size) {
                break;
            }
            int written = snprintf(&dst[out], dst_size - out,
                                   "\\u00%02x", c);
            if (written < 0) {
                break;
            }
            out += (size_t)written;
        } else {
            dst[out++] = (char)c;
        }
    }

    dst[out] = '\0';
    return out;
}

static const char *auth_mode_name(wifi_auth_mode_t authmode) {
    switch (authmode) {
        case WIFI_AUTH_OPEN: return "OPEN";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA";
        case WIFI_AUTH_WPA2_PSK: return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENT";
        default: return "OTHER";
    }
}

static esp_err_t uri_root_get_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    return httpd_resp_send(req, (const char *)page_index, page_index_len);
}

static httpd_uri_t uri_root_get = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = uri_root_get_handler,
    .user_ctx = NULL
};

static esp_err_t uri_reset_head_handler(httpd_req_t *req) {
    ESP_ERROR_CHECK(esp_event_post(
        WEBSERVER_EVENTS,
        WEBSERVER_EVENT_ATTACK_RESET,
        NULL,
        0,
        portMAX_DELAY));

    return httpd_resp_send(req, NULL, 0);
}

static httpd_uri_t uri_reset_head = {
    .uri = "/reset",
    .method = HTTP_HEAD,
    .handler = uri_reset_head_handler,
    .user_ctx = NULL
};

/*
 * Legacy binary AP endpoint is retained for compatibility.
 */
static esp_err_t uri_ap_list_get_handler(httpd_req_t *req) {
    wifictl_scan_nearby_aps();

    const wifictl_ap_records_t *ap_records = wifictl_get_ap_records();
    char resp_chunk[40];

    ESP_ERROR_CHECK(httpd_resp_set_type(req, "application/octet-stream"));

    for (unsigned i = 0; i < ap_records->count; i++) {
        memcpy(resp_chunk, ap_records->records[i].ssid, 33);
        memcpy(&resp_chunk[33], ap_records->records[i].bssid, 6);
        memcpy(&resp_chunk[39], &ap_records->records[i].rssi, 1);
        ESP_ERROR_CHECK(httpd_resp_send_chunk(req, resp_chunk, sizeof(resp_chunk)));
    }

    return httpd_resp_send_chunk(req, NULL, 0);
}

static httpd_uri_t uri_ap_list_get = {
    .uri = "/ap-list",
    .method = HTTP_GET,
    .handler = uri_ap_list_get_handler,
    .user_ctx = NULL
};

static esp_err_t uri_ap_list_api_get_handler(httpd_req_t *req) {
    wifictl_scan_nearby_aps();

    const wifictl_ap_records_t *ap_records = wifictl_get_ap_records();

    ESP_ERROR_CHECK(httpd_resp_set_type(req, "application/json"));

    ESP_ERROR_CHECK(httpd_resp_sendstr_chunk(req, "{"aps":["));

    for (unsigned i = 0; i < ap_records->count; ++i) {
        const wifi_ap_record_t *ap = &ap_records->records[i];

        const size_t ssid_len =
            strnlen((const char *)ap->ssid, sizeof(ap->ssid));

        char escaped_ssid[128];
        char bssid[18];
        char item[320];

        json_escape_bytes(ap->ssid, ssid_len,
                          escaped_ssid, sizeof(escaped_ssid));
        format_mac(ap->bssid, bssid, sizeof(bssid));

        int written = snprintf(
            item,
            sizeof(item),
            "%s{"id":%u,"ssid":"%s","bssid":"%s","
            ""rssi":%d,"channel":%u,"auth":"%s"}",
            i == 0 ? "" : ",",
            i,
            escaped_ssid,
            bssid,
            ap->rssi,
            ap->primary,
            auth_mode_name(ap->authmode));

        if (written < 0 || (size_t)written >= sizeof(item)) {
            ESP_LOGW(TAG, "Skipping AP %u because JSON item is too large", i);
            continue;
        }

        ESP_ERROR_CHECK(httpd_resp_sendstr_chunk(req, item));
    }

    ESP_ERROR_CHECK(httpd_resp_sendstr_chunk(req, "]}"));
    return httpd_resp_sendstr_chunk(req, NULL);
}

static httpd_uri_t uri_ap_list_api_get = {
    .uri = "/api/ap-list",
    .method = HTTP_GET,
    .handler = uri_ap_list_api_get_handler,
    .user_ctx = NULL
};

static esp_err_t uri_run_attack_post_handler(httpd_req_t *req) {
    if (req->content_len != sizeof(attack_request_t)) {
        ESP_LOGW(TAG, "Invalid attack request size: %u", (unsigned)req->content_len);
        return httpd_resp_send_err(
            req,
            HTTPD_400_BAD_REQUEST,
            "Invalid attack request");
    }

    attack_request_t attack_request;
    size_t received = 0;

    while (received < sizeof(attack_request)) {
        int result = httpd_req_recv(
            req,
            ((char *)&attack_request) + received,
            sizeof(attack_request) - received);

        if (result <= 0) {
            ESP_LOGW(TAG, "Failed to receive attack request body");
            return httpd_resp_send_err(
                req,
                HTTPD_400_BAD_REQUEST,
                "Incomplete attack request");
        }

        received += (size_t)result;
    }

    esp_err_t post_result = esp_event_post(
        WEBSERVER_EVENTS,
        WEBSERVER_EVENT_ATTACK_REQUEST,
        &attack_request,
        sizeof(attack_request),
        portMAX_DELAY);

    if (post_result != ESP_OK) {
        ESP_LOGE(TAG, "Unable to queue attack request: %s",
                 esp_err_to_name(post_result));
        return httpd_resp_send_err(
            req,
            HTTPD_500_INTERNAL_SERVER_ERROR,
            "Unable to queue request");
    }

    return httpd_resp_send(req, NULL, 0);
}

static httpd_uri_t uri_run_attack_post = {
    .uri = "/run-attack",
    .method = HTTP_POST,
    .handler = uri_run_attack_post_handler,
    .user_ctx = NULL
};

static esp_err_t uri_status_get_handler(httpd_req_t *req) {
    const attack_status_t *attack_status = attack_get_status();

    ESP_ERROR_CHECK(httpd_resp_set_type(req, "application/octet-stream"));
    ESP_ERROR_CHECK(httpd_resp_send_chunk(
        req,
        (const char *)attack_status,
        4));

    if ((attack_status->state == FINISHED ||
         attack_status->state == TIMEOUT ||
         attack_status->state == FAILED) &&
        attack_status->content_size > 0 &&
        attack_status->content != NULL) {

        ESP_ERROR_CHECK(httpd_resp_send_chunk(
            req,
            attack_status->content,
            attack_status->content_size));
    }

    return httpd_resp_send_chunk(req, NULL, 0);
}

static httpd_uri_t uri_status_get = {
    .uri = "/status",
    .method = HTTP_GET,
    .handler = uri_status_get_handler,
    .user_ctx = NULL
};

static esp_err_t uri_session_get_handler(httpd_req_t *req) {
    capture_session_t session;

    if (!capture_session_get(&session)) {
        return httpd_resp_send_err(
            req,
            HTTPD_500_INTERNAL_SERVER_ERROR,
            "Session unavailable");
    }

    char bssid[18];
    char escaped_ssid[128];
    char json[1024];

    format_mac(session.bssid, bssid, sizeof(bssid));
    json_escape_bytes(
        (const uint8_t *)session.ssid,
        strnlen(session.ssid, sizeof(session.ssid)),
        escaped_ssid,
        sizeof(escaped_ssid));

    const int written = snprintf(
        json,
        sizeof(json),
        "{"
        ""id":%lu,"
        ""state":"%s","
        ""type":"%s","
        ""method":"%s","
        ""timeout_sec":%u,"
        ""elapsed_ms":%lu,"
        ""target":{"
            ""ssid":"%s","
            ""bssid":"%s","
            ""channel":%u,"
            ""rssi":%d"
        "},"
        ""metrics":{"
            ""frames_seen":%lu,"
            ""eapol_frames":%lu,"
            ""pmkid_count":%u,"
            ""last_frame_len":%u,"
            ""pcap_size":%lu"
        "},"
        ""result":{"
            ""size":%u,"
            ""hccapx_ready":%s"
        "}"
        "}",
        (unsigned long)session.id,
        session_state_name(session.state),
        attack_type_name(session.type),
        method_name(session.type, session.method),
        session.timeout_sec,
        (unsigned long)session.elapsed_ms,
        escaped_ssid,
        bssid,
        session.channel,
        session.rssi,
        (unsigned long)session.frames_seen,
        (unsigned long)session.eapol_frames,
        session.pmkid_count,
        session.last_frame_len,
        (unsigned long)session.pcap_size,
        session.result_size,
        session.hccapx_ready ? "true" : "false");

    if (written < 0 || (size_t)written >= sizeof(json)) {
        return httpd_resp_send_err(
            req,
            HTTPD_500_INTERNAL_SERVER_ERROR,
            "Session response too large");
    }

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, json, written);
}

static httpd_uri_t uri_session_get = {
    .uri = "/api/session",
    .method = HTTP_GET,
    .handler = uri_session_get_handler,
    .user_ctx = NULL
};

static esp_err_t uri_capture_pcap_get_handler(httpd_req_t *req) {
    const unsigned size = pcap_serializer_get_size();
    const uint8_t *buffer = pcap_serializer_get_buffer();

    if (buffer == NULL || size == 0) {
        return httpd_resp_send_err(
            req,
            HTTPD_404_NOT_FOUND,
            "No PCAP capture available");
    }

    ESP_LOGD(TAG, "Providing PCAP file");
    httpd_resp_set_type(req, "application/vnd.tcpdump.pcap");
    httpd_resp_set_hdr(
        req,
        "Content-Disposition",
        "attachment; filename="capture.pcap"");

    return httpd_resp_send(
        req,
        (const char *)buffer,
        size);
}

static httpd_uri_t uri_capture_pcap_get = {
    .uri = "/capture.pcap",
    .method = HTTP_GET,
    .handler = uri_capture_pcap_get_handler,
    .user_ctx = NULL
};

static esp_err_t uri_capture_hccapx_get_handler(httpd_req_t *req) {
    hccapx_t *hccapx = hccapx_serializer_get();

    if (hccapx == NULL) {
        return httpd_resp_send_err(
            req,
            HTTPD_404_NOT_FOUND,
            "No completed handshake available");
    }

    ESP_LOGD(TAG, "Providing HCCAPX file");
    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(
        req,
        "Content-Disposition",
        "attachment; filename="capture.hccapx"");

    return httpd_resp_send(
        req,
        (const char *)hccapx,
        sizeof(hccapx_t));
}

static httpd_uri_t uri_capture_hccapx_get = {
    .uri = "/capture.hccapx",
    .method = HTTP_GET,
    .handler = uri_capture_hccapx_get_handler,
    .user_ctx = NULL
};

void webserver_run() {
    ESP_LOGD(TAG, "Running webserver");

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    httpd_handle_t server = NULL;

    ESP_ERROR_CHECK(httpd_start(&server, &config));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_root_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_reset_head));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_ap_list_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_ap_list_api_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_run_attack_post));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_status_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_session_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_capture_pcap_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_capture_hccapx_get));
}
