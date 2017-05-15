#include "esp_event_loop.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "gatts.h"
#include "nvs_flash.h"
#include <string.h>

#define LOG_TAG "MAIN"

int connect_cb(const esp_bd_addr_t addr) {
    ESP_LOGI(LOG_TAG, "Connection from: %02x:%02x:%02x:%02x:%02x:%02x\n", addr[0], addr[1], addr[2], addr[3], addr[4],
             addr[5]);
    return 0;
}

int disconnect_cb(const esp_bd_addr_t addr) {
    ESP_LOGI(LOG_TAG, "Disconnected from: %02x:%02x:%02x:%02x:%02x:%02x\n", addr[0], addr[1], addr[2], addr[3], addr[4],
             addr[5]);

    return 0;
}

int cmd_cb(const char* cmd, size_t size) {
    ESP_LOGI(LOG_TAG, "Command size: %d content: %s", size, cmd);
    gatts_send_response(cmd);
    return 0;
}

void app_main(void) {
    ESP_LOGI(LOG_TAG, "Starting virkey...")
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(init_gatts(connect_cb, disconnect_cb, cmd_cb));
}