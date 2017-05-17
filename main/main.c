#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "gatts.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <string.h>

#define LOG_TAG "MAIN"

// Config stuff
#define CFG_VERSION 1

static struct config_s {
    uint32_t cfg_version;
    uint32_t key_index;
    uint8_t id[6];
    uint8_t master_key[16];
} __attribute__((packed)) config;

static nvs_handle nvs_config_h;
// --- End Config stuff

// Session stuff
static struct session_s {
    uint8_t derived_key[32];
    uint32_t nounce;
    uint8_t address[6];
    bool connected;
} session;
// --- End Session stuff

int connect_cb(const esp_bd_addr_t addr) {
    if(session.connected) {
        return 1;
    }
    memset(&session, 0, sizeof(session));
    memcpy(&session.address, addr, sizeof(session.address));
    session.nounce = esp_random();
    session.connected = true;

    ESP_LOGI(LOG_TAG, "Connection from: %02x:%02x:%02x:%02x:%02x:%02x\n", session.address[0], session.address[1],
             session.address[2], session.address[3], session.address[4], session.address[5]);
    return 0;
}

int disconnect_cb(const esp_bd_addr_t addr) {
    if(!session.connected) {
        return 1;
    }
    session.connected = false;
    ESP_LOGI(LOG_TAG, "Disconnected from: %02x:%02x:%02x:%02x:%02x:%02x\n", session.address[0], session.address[1],
             session.address[2], session.address[3], session.address[4], session.address[5]);

    return 0;
}

int cmd_cb(const char* cmd, size_t size) {
    ESP_LOGI(LOG_TAG, "Command size: %d content: %s", size, cmd);
    gatts_send_response(cmd);
    return 0;
}

static esp_err_t init_flash() {
    esp_err_t err = nvs_flash_init();
    if(err == ESP_ERR_NVS_NO_FREE_PAGES) {
        // NVS partition was truncated and needs to be erased
        const esp_partition_t* nvs_partition =
            esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, NULL);
        assert(nvs_partition && "partition table must have an NVS partition");
        ESP_ERROR_CHECK(esp_partition_erase_range(nvs_partition, 0, nvs_partition->size));
        // Retry nvs_flash_init
        err = nvs_flash_init();
    }
    return err;
}

static esp_err_t save_flash_config() {
    esp_err_t err;

    err = nvs_set_blob(nvs_config_h, "config", &config, sizeof(config));
    if(err != ESP_OK) {
        goto fail;
    }
    err = nvs_commit(nvs_config_h);
    if(err != ESP_OK)
        goto fail;
    ESP_LOGI(LOG_TAG, "Config writen to flash!\n");
    return err;

fail:
    ESP_LOGE(LOG_TAG, "Error (%d) writing config to flash!\n", err);
    return err;
}

static esp_err_t reset_flash_config() {
    esp_err_t err = ESP_OK;

    ESP_LOGI(LOG_TAG, "Reseting flash config...\n");
    memset(&config, 0, sizeof(config));
    config.cfg_version = CFG_VERSION;
    config.key_index = 0;
    for(int i = 0; i < 6; i++) {
        config.id[i] = (uint8_t)(esp_random() & 0xff);
    }
    for(int i = 0; i < 16; i++) {
        config.master_key[i] = (uint8_t)(esp_random() & 0xff);
    }

    err = save_flash_config();
    return err;
}

static esp_err_t load_flash_config() {
    esp_err_t err = nvs_open("virkey", NVS_READWRITE, &nvs_config_h);
    if(err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "Error (%d) opening nvs config handle\n", err);
        return err;
    }

    size_t size;
    err = nvs_get_blob(nvs_config_h, "config", NULL, &size); // Get blob size
    if(err != ESP_OK) {
        if(err == ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(LOG_TAG, "config not found, creating new one\n");
            err = reset_flash_config();
            if(err != ESP_OK) {
                goto fail;
            }
            err = nvs_get_blob(nvs_config_h, "config", NULL, &size); // Get blob size 2nd attempt
            if(err != ESP_OK) {
                goto fail;
            }

        } else {
            ESP_LOGE(LOG_TAG, "Error (%d) reading config blob size\n", err);
            goto fail;
        }
    }
    if(size != sizeof(config)) {
        ESP_LOGW(LOG_TAG, "Config size mismatch!\n")
        if(size > sizeof(config)) {
            size = sizeof(config);
        }
    }
    err = nvs_get_blob(nvs_config_h, "config", &config, &size); // Get blob size
    if(err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "Error (%d) reading config\n", err)
        goto fail;
    }
    ESP_LOGI(LOG_TAG, "Config loaded\n")
    return ESP_OK;
fail:
    return err;
}

void app_main(void) {
    ESP_LOGI(LOG_TAG, "Starting virkey...")
    ESP_ERROR_CHECK(init_flash());
    ESP_ERROR_CHECK(load_flash_config());
    ESP_LOGI(LOG_TAG, "device id: %02x%02x%02x%02x%02x%02x\n", config.id[5], config.id[4], config.id[3], config.id[2],
             config.id[1], config.id[0]);
    ESP_ERROR_CHECK(init_gatts(connect_cb, disconnect_cb, cmd_cb, config.key_index, config.id));
}