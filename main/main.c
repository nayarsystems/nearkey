#include <string.h>

#include "cJSON.h"
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
    SemaphoreHandle_t sem;
    uint8_t derived_key[32];
    cJSON* login_obj;
    char* nonce;
    char* rnonce;
    uint8_t address[6];
    bool login;
    int conn_timeout;
    bool connected;
} session;
// --- End Session stuff

static char* nonce_str() {
    uint8_t bin[16];
    size_t olen = 0;

    for(size_t i = 0; i < sizeof(bin); i++) {
        bin[i] = esp_random() & 0xff;
    }
    mbedtls_base64_encode(NULL, 0, &olen, bin, sizeof(bin));

    char* nonce = calloc(1, olen + 1);
    mbedtls_base64_encode((uint8_t*)nonce, olen, &olen, bin, sizeof(bin));

    return nonce;
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

static void bin2b64(const uint8_t* buf, size_t sz, char* dst, size_t dst_sz) {
    mbedtls_base64_encode((uint8_t*)dst, dst_sz, &dst_sz, buf, sz);
    dst[dst_sz] = 0;
}

static int respond(cJSON* resp) {
    int res = 0;
    char* json_str = NULL;
    char* b64_str = NULL;
    char* sign_str = NULL;
    char* res_str = NULL;
    uint8_t sign_bin[32];
    mbedtls_sha256_context sha256_ctx = {};
    size_t olen = 0;

    // Append n and x nonce fields
    cJSON_AddStringToObject(resp, "n", session.nonce);
    cJSON_AddStringToObject(resp, "x", session.rnonce);
    json_str = cJSON_PrintUnformatted(resp);
    if(json_str == NULL) {
        ESP_LOGE("RESPOND", "Fail encoding JSON data");
        res = 1;
        goto exitfn;
    }
    ESP_LOGI("RESPOND", "JSON response: %s", json_str);
    mbedtls_base64_encode(NULL, 0, &olen, (uint8_t*)json_str, strlen(json_str));
    b64_str = calloc(1, olen + 1);
    if(b64_str == NULL) {
        ESP_LOGE("RESPOND", "Unable to alloc %d for b64 data", olen);
        res = 1;
        goto exitfn;
    }
    mbedtls_base64_encode((uint8_t*)b64_str, olen, &olen, (uint8_t*)json_str, strlen(json_str));

    // Compute signature
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, (uint8_t*)b64_str, strlen(b64_str));
    mbedtls_sha256_update(&sha256_ctx, session.derived_key, sizeof(session.derived_key));
    mbedtls_sha256_finish(&sha256_ctx, sign_bin);
    mbedtls_sha256_free(&sha256_ctx);
    mbedtls_base64_encode(NULL, 0, &olen, sign_bin, sizeof(sign_bin));
    sign_str = calloc(1, olen + 1);
    if(sign_str == NULL) {
        ESP_LOGE("RESPOND", "Unable to alloc %d for signature data", olen);
        res = 1;
        goto exitfn;
    }
    mbedtls_base64_encode((uint8_t*)sign_str, olen, &olen, sign_bin, sizeof(sign_bin));
    asprintf(&res_str, "%s %s", b64_str, sign_str);
    gatts_send_response(res_str);
    ESP_LOGI("RESPOND", "Raw response: %s", res_str);

exitfn:
    if(json_str != NULL) {
        free(json_str);
    }
    if(b64_str != NULL) {
        free(b64_str);
    }
    if(sign_str != NULL) {
        free(sign_str);
    }
    if(res_str != NULL) {
        free(res_str);
    }
    return res;
}

static int do_login(const char* cmd) {
    int ret = 0;
    str_list *sl = NULL, *pl = NULL;
    size_t olen = 0;
    mbedtls_sha256_context sha256_ctx = {};
    char chbuf[128];
    char* json_data = NULL;
    cJSON* json_item = NULL;
    cJSON* json_resp = NULL;

    sl = pl = str_split(cmd, " ");
    if(str_list_len(sl) != 2) {
        ESP_LOGE("LOGIN", "invalid login data (split data/nonce)");
        ret = 1;
        goto exitfn;
    }

    // Calculate derived key
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, (uint8_t*)sl->s, strlen(sl->s));
    mbedtls_sha256_update(&sha256_ctx, config.master_key, sizeof(config.master_key));
    mbedtls_sha256_finish(&sha256_ctx, session.derived_key);
    mbedtls_sha256_free(&sha256_ctx);
    bin2b64(session.derived_key, sizeof(session.derived_key), chbuf, sizeof(chbuf));
    ESP_LOGI("LOGIN", "Derived key: %s", chbuf);

    if(mbedtls_base64_decode(NULL, 0, &olen, (uint8_t*)pl->s, strlen(pl->s)) != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        ESP_LOGE("LOGIN", "invalid base64 data (probe)");
        ret = 1;
        goto exitfn;
    }
    json_data = calloc(1, olen + 1);
    if(mbedtls_base64_decode((uint8_t*)json_data, olen, &olen, (uint8_t*)pl->s, strlen(pl->s)) != 0) {
        ESP_LOGE("LOGIN", "invalid base64 data");
        ret = 1;
        goto exitfn;
    }
    ESP_LOGI("LOGIN", "json str: %s", json_data);
    pl = pl->next;

    // Set Session rnonce
    SETPTR(session.rnonce, strdup(pl->s));

    // Decode json_data
    SETPTR_cJSON(session.login_obj, cJSON_Parse(json_data));
    if(session.login_obj == NULL) {
        ESP_LOGE("LOGIN", "invalid json data");
        ret = 1;
        goto exitfn;
    }
    if(!(session.login_obj->type & cJSON_Object)) {
        ESP_LOGE("LOGIN", "json login is not object type");
        ret = 1;
        goto exitfn;
    }
    json_item = cJSON_GetObjectItem(session.login_obj, "t");
    if(json_item == NULL) {
        ESP_LOGE("LOGIN", "login object hasn't [t] entry");
        ret = 1;
        goto exitfn;
    }
    if(!(json_item->type & cJSON_String)) {
        ESP_LOGE("LOGIN", "json entry [t] isn't string type");
        ret = 1;
        goto exitfn;
    }
    if(strcmp(json_item->valuestring, "login") != 0) {
        ESP_LOGE("LOGIN", "First command must be \"login\" type");
        ret = 1;
        goto exitfn;
    }

    json_resp = cJSON_CreateObject();
    cJSON_AddStringToObject(json_resp, "res", "ok");
    ret = respond(json_resp);
    if(ret) {
        ESP_LOGE("LOGIN", "Fail sending response");
        goto exitfn;
    }

    session.login = true;
    ret = 0;
exitfn:
    if(sl != NULL) {
        str_list_free(sl);
    }
    if(json_data != NULL) {
        free(json_data);
    }
    if(json_resp != NULL) {
        cJSON_Delete(json_resp);
    }
    return ret;
}

static int do_cmd(const char* cmd) {
    return 0;
}

static int connect_cb(const esp_bd_addr_t addr) {
    int ret = 0;

    while(!xSemaphoreTake(session.sem, portMAX_DELAY))
        ;
    if(session.connected) {
        ret = 1;
        goto exitfn;
    }
    memcpy(&session.address, addr, sizeof(session.address));
    SETPTR(session.nonce, nonce_str());
    session.conn_timeout = DEF_CONN_TIMEOUT;
    session.connected = true;
    session.login = false;
    ESP_LOGI(LOG_TAG, "Connection from: %02x:%02x:%02x:%02x:%02x:%02x", session.address[0], session.address[1],
             session.address[2], session.address[3], session.address[4], session.address[5]);
    ESP_LOGI(LOG_TAG, "First nonce: %s", session.nonce);
exitfn:
    xSemaphoreGive(session.sem);
    return ret;
}

static int disconnect_cb(const esp_bd_addr_t addr) {
    int ret = 0;

    while(!xSemaphoreTake(session.sem, portMAX_DELAY))
        ;
    if(!session.connected) {
        ret = 1;
        goto exitfn;
    }
    session.connected = false;
    ESP_LOGI(LOG_TAG, "Disconnected from: %02x:%02x:%02x:%02x:%02x:%02x", session.address[0], session.address[1],
             session.address[2], session.address[3], session.address[4], session.address[5]);
exitfn:
    xSemaphoreGive(session.sem);
    return ret;
}

static int cmd_cb(const char* cmd, size_t size) {
    int ret = 0;

    while(!xSemaphoreTake(session.sem, portMAX_DELAY))
        ;
    ESP_LOGI(LOG_TAG, "Command size: %d content: %s", size, cmd);
    if(!session.login) {
        if(do_login(cmd) != 0) {
            ret = 1;
            goto exitfn;
        }
    } else {
        if(do_cmd(cmd) != 0) {
            ret = 1;
            goto exitfn;
        }
    }
    session.conn_timeout = DEF_CONN_TIMEOUT;
// gatts_send_response(cmd);
exitfn:
    xSemaphoreGive(session.sem);
    return ret;
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
    esp_err_t err = ESP_OK;

    err = nvs_set_blob(nvs_config_h, "config", &config, sizeof(config));
    if(err != ESP_OK) {
        goto exitfn;
    }
    err = nvs_commit(nvs_config_h);
    if(err != ESP_OK)
        goto exitfn;
    ESP_LOGI(LOG_TAG, "Config writen to flash!");
    err = ESP_OK;
exitfn:
    if(err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "Error (%d) writing config to flash!", err);
    }
    return err;
}

static esp_err_t reset_flash_config() {
    esp_err_t err = ESP_OK;

    ESP_LOGI(LOG_TAG, "Reseting flash config...");
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
        ESP_LOGE(LOG_TAG, "Error (%d) opening nvs config handle", err);
        goto exitfn;
    }
    size_t size;
    err = nvs_get_blob(nvs_config_h, "config", NULL, &size); // Get blob size
    if(err != ESP_OK) {
        if(err == ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(LOG_TAG, "config not found, creating new one");
            err = reset_flash_config();
            if(err != ESP_OK) {
                goto exitfn;
            }
            err = nvs_get_blob(nvs_config_h, "config", NULL, &size); // Get blob size 2nd attempt
            if(err != ESP_OK) {
                goto exitfn;
            }

        } else {
            ESP_LOGE(LOG_TAG, "Error (%d) reading config blob size", err);
            goto exitfn;
        }
    }
    if(size != sizeof(config)) {
        ESP_LOGW(LOG_TAG, "Config size mismatch!")
        if(size > sizeof(config)) {
            size = sizeof(config);
        }
    }
    err = nvs_get_blob(nvs_config_h, "config", &config, &size); // Get blob size
    if(err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "Error (%d) reading config!", err)
        goto exitfn;
    }
    ESP_LOGI(LOG_TAG, "Config loaded")
    err = ESP_OK;
exitfn:
    return err;
}

void app_main(void) {
    char chbuf[65];

    ESP_LOGI(LOG_TAG, "Starting virkey...")
    session.sem = xSemaphoreCreateMutex();
    xSemaphoreGive(session.sem);
    ESP_ERROR_CHECK(init_flash());
    ESP_ERROR_CHECK(load_flash_config());
    bin2hex(config.id, 6, chbuf, sizeof(chbuf));
    ESP_LOGI(LOG_TAG, "device id: %s", chbuf);
    bin2b64(config.master_key, 16, chbuf, sizeof(chbuf));
    ESP_LOGI(LOG_TAG, "master key: %s", chbuf);

    ESP_ERROR_CHECK(init_gatts(connect_cb, disconnect_cb, cmd_cb, config.key_index, config.id));

    while(1) {
        vTaskDelay(100 / portTICK_PERIOD_MS);
        while(!xSemaphoreTake(session.sem, portMAX_DELAY))
            ;
        if(session.connected) {
            if(session.conn_timeout > 0) {
                session.conn_timeout--;
            } else {
                ESP_LOGE(LOG_TAG, "Watch dog disconnection");
                session.conn_timeout = DEF_CONN_TIMEOUT;
                gatts_close_connection();
            }
        }
        xSemaphoreGive(session.sem);
    }
}