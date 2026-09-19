set(WEB_ROOT "\${CMAKE_CURRENT_LIST_DIR}")
set(WEB_GEN_DIR "\${CMAKE_CURRENT_BINARY_DIR}/generated")
set(WEB_HTML "\${WEB_ROOT}/utils/index.html")
set(WEB_HEADER "\${WEB_GEN_DIR}/page_index.h")

file(MAKE_DIRECTORY "\${WEB_GEN_DIR}")

find_package(Python3 REQUIRED COMPONENTS Interpreter)
execute_process(
    COMMAND "\${Python3_EXECUTABLE}" "\${WEB_ROOT}/utils/generate_page_header.py"
            "\${WEB_HTML}" "\${WEB_HEADER}"
    RESULT_VARIABLE WEB_GEN_RESULT
)

if(NOT WEB_GEN_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to generate compressed web UI header")
endif()

idf_component_register(SRCS "webserver.c"
                    INCLUDE_DIRS "interface" "\${WEB_GEN_DIR}"
                    PRIV_REQUIRES hccapx_serializer pcap_serializer esp_http_server wifi_controller main)
