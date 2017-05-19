#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "gatts.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "parseutils.h"
#include "utils.h"
#include <stdatomic.h>
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
#define DEF_CONN_TIMEOUT 100
static struct session_s {
    uint8_t derived_key[32];
    char* nounce;
    char* rnounce;
    uint8_t address[6];
    bool login;
    atomic_int conn_timeout;
    atomic_bool connected;

} session;
// --- End Session stuff

static char* nounce_str() {
    uint8_t bin[16];
    size_t olen = 0;

    for(size_t i = 0; i < sizeof(bin); i++) {
        bin[i] = esp_random() & 0xff;
    }
    mbedtls_base64_encode(NULL, 0, &olen, bin, sizeof(bin));

    char* nounce = calloc(1, olen);
    mbedtls_base64_encode((uint8_t*)nounce, olen, &olen, bin, sizeof(bin));

    return nounce;
}

static void bin2hex(const uint8_t* buf, size_t sz, char* dst, size_t dst_sz) {
    const char* hexconv = "0123456789abcdef";

    while(sz > 0 && dst_sz > 2) {
        *dst = hexconv[((*buf) >> 4) & 0x0f];
        dst++;
        dst_sz--;
        *dst = hexconv[(*buf) & 0x0f];
        dst++;
        dst_sz--;
        buf++;
        sz--;
    }
    *dst = 0;
}

static int do_login(const char* cmd) {
    int rv = 0;
    str_list *sl = NULL, *pl = NULL;
    char* json_data = NULL;
    size_t olen = 0;

    sl = pl = str_split(cmd, " ");
    if(str_list_len(sl) != 2) {
        ESP_LOGE("LOGIN", "invalid login data (split data/nounce)");
        goto fail;
    }
    if(mbedtls_base64_decode(NULL, 0, &olen, (uint8_t*)pl->s, strlen(pl->s)) != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        ESP_LOGE("LOGIN", "invalid base64 data (probe)");
        goto fail;
    }
    json_data = calloc(1, olen);
    if(mbedtls_base64_decode((uint8_t*)json_data, olen, &olen, (uint8_t*)pl->s, strlen(pl->s)) != 0) {
        ESP_LOGE("LOGIN", "invalid base64 data");
        goto fail;
    }
    ESP_LOGI("login", "Login data: %s\n", json_data);

    goto ok;
fail:
    rv = 1;
ok:
    if(sl != NULL) {
        str_list_free(sl);
    }
    if(json_data != NULL) {
        free(json_data);
    }
    return rv;
}

static int do_cmd(const char* cmd) {
    return 0;
}

static int connect_cb(const esp_bd_addr_t addr) {
    if(atomic_load(&session.connected)) {
        return 1;
    }
    memset(&session, 0, sizeof(session));
    memcpy(&session.address, addr, sizeof(session.address));
    SETPTR(session.nounce, nounce_str(16));
    atomic_store(&session.conn_timeout, DEF_CONN_TIMEOUT);
    atomic_store(&session.connected, true);

    ESP_LOGI(LOG_TAG, "Connection from: %02x:%02x:%02x:%02x:%02x:%02x\n", session.address[0], session.address[1],
             session.address[2], session.address[3], session.address[4], session.address[5]);
    ESP_LOGI(LOG_TAG, "First NOUNCE: %s\n", session.nounce);
    return 0;
}

static int disconnect_cb(const esp_bd_addr_t addr) {
    if(!atomic_load(&session.connected)) {
        return 1;
    }
    atomic_store(&session.connected, false);
    ESP_LOGI(LOG_TAG, "Disconnected from: %02x:%02x:%02x:%02x:%02x:%02x\n", session.address[0], session.address[1],
             session.address[2], session.address[3], session.address[4], session.address[5]);

    return 0;
}

static int cmd_cb(const char* cmd, size_t size) {
    ESP_LOGI(LOG_TAG, "Command size: %d content: %s", size, cmd);
    if(!session.login) {
        if(do_login(cmd) != 0) {
            return 1;
        }
    } else {
        if(do_cmd(cmd) != 0) {
            return 1;
        }
    }
    atomic_store(&session.conn_timeout, DEF_CONN_TIMEOUT);
    // gatts_send_response(cmd);
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
    char chbuf[65];
    ESP_LOGI(LOG_TAG, "Starting virkey...")
    ESP_ERROR_CHECK(init_flash());
    ESP_ERROR_CHECK(load_flash_config());
    bin2hex(config.id, 6, chbuf, sizeof(chbuf));
    ESP_LOGI(LOG_TAG, "device id: %s\n", chbuf);
    bin2hex(config.master_key, 16, chbuf, sizeof(chbuf));
    ESP_LOGI(LOG_TAG, "master key: %s\n", chbuf);

    ESP_ERROR_CHECK(init_gatts(connect_cb, disconnect_cb, cmd_cb, config.key_index, config.id));

    while(1) {
        vTaskDelay(100 / portTICK_PERIOD_MS);

        if(atomic_load(&session.connected)) {

            if(atomic_load(&session.conn_timeout) > 0) {
                atomic_fetch_sub(&session.conn_timeout, 1);
            } else {
                ESP_LOGI(LOG_TAG, "Watch dog disconnection\n");
                atomic_store(&session.conn_timeout, DEF_CONN_TIMEOUT);
                gatts_close_connection();
            }
        }
    }
}