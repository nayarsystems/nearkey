#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "driver/gpio.h"
#include "esp_bt_defs.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "gatts.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "parseutils.h"
#include "utils.h"

#define LOG_TAG "MAIN"

// Errors
#define ERR_OLD_KEY_VERSION 1
#define ERR_OLD_KEY_VERSION_S "Old Key version"
#define ERR_PERMISSION_DENIED 2
#define ERR_PERMISSION_DENIED_S "Permission denied"
#define ERR_UNKNOWN_COMMAND 3
#define ERR_UNKNOWN_COMMAND_S "Unknown command"
// --- End Errors

// Function definitions
static esp_err_t save_flash_config();
// --- End Function definitions

// Config stuff
#define CFG_VERSION 2

static struct config_s {
    uint32_t cfg_version;
    uint32_t key_version;
    uint32_t cmd_version;
    uint8_t master_key[32];
} __attribute__((packed)) config;

static nvs_handle nvs_config_h;
// --- End Config stuff

// Session stuff
#define DEF_SIGNATURE_SIZE 16
#define DEF_CONN_TIMEOUT 50
static struct session_s {
    SemaphoreHandle_t sem;
    uint32_t key_version;
    uint8_t derived_key[32];
    cJSON* login_obj;
    uint64_t nonce;
    uint64_t rnonce;
    uint8_t address[6];
    bool login;
    int conn_timeout;
    bool connected;
    bool smart_reboot;
} session;
// --- End Session stuff

// Actuator timers
#define DEF_ACT_TIMEOUT 30
static uint32_t act0_tm;
// --- End Actuator timers

// Reset timer
static uint32_t reset_tm;
static bool erase_on_reset;
// --- End Reset timer

/*static void bin2hex(const uint8_t* buf, size_t sz, char* dst, size_t dst_sz) {
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
}*/

static void bin2b64(const uint8_t* buf, size_t sz, char* dst, size_t dst_sz) {
    mbedtls_base64_encode((uint8_t*)dst, dst_sz, &dst_sz, buf, sz);
    dst[dst_sz] = 0;
}

static int respond(cJSON* resp, bool add_nonce) {
    int res = 0;
    char* json_str = NULL;
    char* sign_str = NULL;
    char* res_str = NULL;
    uint8_t sign_bin[32];
    char nonce_str[32];
    mbedtls_sha256_context sha256_ctx = {};
    size_t olen = 0;

    // Append n and x nonce fields
    if(add_nonce) {
        snprintf(nonce_str, sizeof(nonce_str), "%llu", session.nonce);
        cJSON_AddStringToObject(resp, "n", nonce_str);
    }
    json_str = cJSON_PrintUnformatted(resp);
    if(json_str == NULL) {
        ESP_LOGE("RESPOND", "Fail encoding JSON data");
        res = 1;
        goto exitfn;
    }
    ESP_LOGI("RESPOND", "JSON response: %s", json_str);

    // Compute signature
    snprintf(nonce_str, sizeof(nonce_str), "%llu", session.rnonce);
    ESP_LOGI("RESPOND", "Responding with nonce: \"%s\"", nonce_str);
    session.rnonce++; // Increment rnonce for next response
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, (uint8_t*)json_str, strlen(json_str));
    mbedtls_sha256_update(&sha256_ctx, (uint8_t*)nonce_str, strlen(nonce_str));
    mbedtls_sha256_update(&sha256_ctx, session.derived_key, sizeof(session.derived_key));
    mbedtls_sha256_finish(&sha256_ctx, sign_bin);
    mbedtls_sha256_free(&sha256_ctx);
    mbedtls_base64_encode(NULL, 0, &olen, sign_bin, sizeof(sign_bin));
    sign_str = calloc(1, olen + 1);
    if(sign_str == NULL) {
        res = 1;
        goto exitfn;
    }
    mbedtls_base64_encode((uint8_t*)sign_str, olen, &olen, sign_bin, DEF_SIGNATURE_SIZE);
    asprintf(&res_str, "%s~%s", json_str, sign_str);
    gatts_send_response(res_str);
    ESP_LOGI("RESPOND", "Raw response: %s", res_str);

exitfn:
    if(json_str != NULL) {
        free(json_str);
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
    char* json_data;
    char* nonce_data;
    cJSON* json_item = NULL;
    cJSON* json_resp = NULL;

    sl = pl = str_split_safe(cmd, "~");
    if(str_list_len(sl) != 2) {
        ESP_LOGE("LOGIN", "Invalid login data (split data/nonce)");
        ret = 1;
        goto exitfn;
    }

    json_data = pl->s;
    pl = pl->next;
    nonce_data = pl->s;

    ESP_LOGI("LOGIN", "Command: %s", json_data);

    // Set Session rnonce
    session.rnonce = strtoull(nonce_data, NULL, 10);

    // Decode json_data
    SETPTR_cJSON(session.login_obj, cJSON_Parse(json_data));
    if(session.login_obj == NULL) {
        ESP_LOGE("LOGIN", "Invalid json data");
        ret = 1;
        goto exitfn;
    }
    if(!(session.login_obj->type & cJSON_Object)) {
        ESP_LOGE("LOGIN", "JSON login is not object type");
        ret = 1;
        goto exitfn;
    }
    json_item = cJSON_GetObjectItem(session.login_obj, "t");
    if(json_item == NULL) {
        ESP_LOGE("LOGIN", "Login object hasn't [t] entry");
        ret = 1;
        goto exitfn;
    }
    if(!(json_item->type & cJSON_String)) {
        ESP_LOGE("LOGIN", "JSON entry [t] isn't string type");
        ret = 1;
        goto exitfn;
    }
    if(strcmp(json_item->valuestring, "l") != 0) {
        ESP_LOGE("LOGIN", "First command must be \"l\" type");
        ret = 1;
        goto exitfn;
    }
    json_item = cJSON_GetObjectItem(session.login_obj, "v");
    if(json_item == NULL) {
        ESP_LOGE("LOGIN", "Login object hasn't [v] entry");
        ret = 1;
        goto exitfn;
    }
    if(!(json_item->type & cJSON_Number)) {
        ESP_LOGE("LOGIN", "JSON entry [v] isn't number type");
        ret = 1;
        goto exitfn;
    }
    session.key_version = json_item->valueint;

    if(config.key_version == 0) {
        if(session.key_version < 1) {
            ESP_LOGE("LOGIN", "lock is unformated and v <  1");
            ret = 1;
            goto exitfn;
        }
        json_item = cJSON_GetObjectItem(session.login_obj, "m");
        if(json_item == NULL) {
            ESP_LOGE("LOGIN", "Login object hasn't [m] entry and lock is unformated");
            ret = 1;
            goto exitfn;
        }
        if(!(json_item->type & cJSON_String)) {
            ESP_LOGE("LOGIN", "JSON entry [m] isn't string type");
            ret = 1;
            goto exitfn;
        }
        if(mbedtls_base64_decode(config.master_key, sizeof(config.master_key), &olen, (uint8_t*)json_item->valuestring,
                                 strlen(json_item->valuestring)) != 0) {
            ESP_LOGE("LOGIN", "Error decoding master key.");
            ret = 1;
            goto exitfn;
        }
        if(olen != sizeof(config.master_key)) {
            ESP_LOGE("LOGIN", "Master key size mismatch: %d != %d", olen, sizeof(config.master_key));
            ret = 1;
            goto exitfn;
        }
        config.key_version = session.key_version;
        save_flash_config();
        session.smart_reboot = true;
    }

    json_resp = cJSON_CreateObject();
    if(session.key_version < config.key_version) {
        cJSON_AddNumberToObject(json_resp, "e", ERR_OLD_KEY_VERSION);
        cJSON_AddStringToObject(json_resp, "d", ERR_OLD_KEY_VERSION_S);
        ret = 2;
        goto exitresp;
    }

    cJSON_AddStringToObject(json_resp, "r", "ok");
    session.login = true;

exitresp:
    // Calculate derived key
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, (uint8_t*)sl->s, strlen(sl->s));
    mbedtls_sha256_update(&sha256_ctx, config.master_key, sizeof(config.master_key));
    mbedtls_sha256_finish(&sha256_ctx, session.derived_key);
    mbedtls_sha256_free(&sha256_ctx);
    bin2b64(session.derived_key, sizeof(session.derived_key), chbuf, sizeof(chbuf));
    ESP_LOGI("LOGIN", "Derived key: %s", chbuf);
    if(respond(json_resp, true) != 0) {
        ESP_LOGE("LOGIN", "Fail sending response");
        ret = 1;
        goto exitfn;
    }

exitfn:
    if(sl != NULL) {
        str_list_free(sl);
    }
    if(json_resp != NULL) {
        cJSON_Delete(json_resp);
    }
    return ret;
}

static int do_cmd(const char* cmd) {
    int ret = 0;
    str_list *sl = NULL, *pl = NULL;
    size_t olen = 0;
    mbedtls_sha256_context sha256_ctx = {};
    uint8_t sig_calc[32] = {0};
    uint8_t sig_peer[32] = {0};
    char nonce_str[32] = {0};
    char* cmd_str = NULL;
    char* json_data = NULL;
    char* sign_data = NULL;
    cJSON* json_cmd = NULL;
    cJSON* json_item = NULL;
    cJSON* json_resp = NULL;

    ESP_LOGI("CMD", "raw cmd: %s", cmd);
    sl = pl = str_split_safe(cmd, "~");
    if(str_list_len(sl) != 2) {
        ESP_LOGE("CMD", "Invalid command data (split data/signature)");
        ret = 1;
        goto exitfn;
    }

    json_data = pl->s;
    pl = pl->next;
    sign_data = pl->s;

    // Calculate signature
    snprintf(nonce_str, sizeof(nonce_str), "%llu", session.nonce);
    ESP_LOGE("CMD", "Nonce esperado: %s", nonce_str);
    session.nonce++; // Increment nonce for next command
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, (uint8_t*)json_data, strlen(json_data));
    mbedtls_sha256_update(&sha256_ctx, (uint8_t*)nonce_str, strlen(nonce_str));
    mbedtls_sha256_update(&sha256_ctx, session.derived_key, sizeof(session.derived_key));
    mbedtls_sha256_finish(&sha256_ctx, sig_calc);
    mbedtls_sha256_free(&sha256_ctx);

    // Check signature
    olen = sizeof(sig_peer);
    if(mbedtls_base64_decode(sig_peer, olen, &olen, (uint8_t*)sign_data, strlen(sign_data)) != 0) {
        ESP_LOGE("CMD", "Invalid b64 signature");
        ret = 1;
        goto exitfn;
    }
    if(olen < 16) {
        ESP_LOGE("CMD", "Signature too short (%d)", olen);
        ret = 1;
        goto exitfn;
    }
    if(memcmp(sig_calc, sig_peer, olen) != 0) {
        ESP_LOGE("CMD", "Signature don't match");
        ret = 1;
        goto exitfn;
    }

    // Decode json data
    json_cmd = cJSON_Parse(json_data);
    if(json_cmd == NULL) {
        ESP_LOGE("CMD", "Malformed JSON data");
        ret = 1;
        goto exitfn;
    }
    if(!(json_cmd->type & cJSON_Object)) {
        ESP_LOGE("CMD", "JSON is not object type");
        ret = 1;
        goto exitfn;
    }
    json_item = cJSON_GetObjectItem(json_cmd, "t");
    if(json_item == NULL) {
        ESP_LOGE("CMD", "Cmd object hasn't [t] entry");
        ret = 1;
        goto exitfn;
    }
    if(!(json_item->type & cJSON_String)) {
        ESP_LOGE("CMD", "Entry [t] isn't string type");
        ret = 1;
        goto exitfn;
    }
    cmd_str = json_item->valuestring;
    ESP_LOGI("CMD", "Executing CMD: %s", cmd_str);

    json_resp = cJSON_CreateObject();
    if(strcmp(cmd_str, "q") == 0) { // Quit
        session.conn_timeout = 2;
        session.login = false;
        cJSON_AddStringToObject(json_resp, "r", "ok");
        ret = 2;
        goto exitresp;
    }
    if(strcmp(cmd_str, "n") == 0) { // Nop
        cJSON_AddStringToObject(json_resp, "r", "ok");
        ret = 0;
        goto exitresp;
    }

    if(strcmp(cmd_str, "a0") == 0) { // Actuator
        cJSON_AddStringToObject(json_resp, "r", "ok");
        act0_tm = DEF_ACT_TIMEOUT;
        ret = 0;
        goto exitresp;
    }

    cJSON_AddNumberToObject(json_resp, "e", ERR_UNKNOWN_COMMAND);
    cJSON_AddStringToObject(json_resp, "d", ERR_UNKNOWN_COMMAND_S);
    ret = 2;

exitresp:
    if(respond(json_resp, false) != 0) {
        ESP_LOGE("LOGIN", "Fail sending response");
        ret = 1;
        goto exitfn;
    }

exitfn:
    if(sl != NULL) {
        str_list_free(sl);
    }
    if(json_cmd != NULL) {
        cJSON_Delete(json_cmd);
    }
    if(json_resp != NULL) {
        cJSON_Delete(json_resp);
    }
    return ret;
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
    session.conn_timeout = DEF_CONN_TIMEOUT;
    session.connected = true;
    session.nonce = esp_random();
    session.login = false;
    ESP_LOGI(LOG_TAG, "Connection from: %02x:%02x:%02x:%02x:%02x:%02x", session.address[0], session.address[1],
             session.address[2], session.address[3], session.address[4], session.address[5]);
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
    if(session.smart_reboot) {
        reset_tm = 1;
    }
    xSemaphoreGive(session.sem);
    return ret;
}

static int cmd_cb(const char* cmd, size_t size) {
    int ret = 0;

    while(!xSemaphoreTake(session.sem, portMAX_DELAY))
        ;
    ESP_LOGI(LOG_TAG, "Command size: %d content: %s", size, cmd);
    if(!session.login) {
        ret = do_login(cmd);
    } else {
        ret = do_cmd(cmd);
        if(ret == 0 && config.key_version < session.key_version) {
            config.key_version = session.key_version;
            save_flash_config();
            session.smart_reboot = true;
        }
    }
    if(ret == 0) {
        session.conn_timeout = DEF_CONN_TIMEOUT;
    } else if(ret == 2) {
        ret = 0;
    }

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
    config.key_version = 0;
    memset(config.master_key, 0, sizeof(config.master_key));
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

static void setup_gpio() {
    gpio_config_t io_conf;
    // disable interrupt
    io_conf.intr_type = GPIO_PIN_INTR_DISABLE;
    // set as output mode
    io_conf.mode = GPIO_MODE_OUTPUT;
    // bit mask of the pins that you want to set,e.g.GPIO18/19
    io_conf.pin_bit_mask = (1 << 23);
    // disable pull-down mode
    io_conf.pull_down_en = 0;
    // disable pull-up mode
    io_conf.pull_up_en = 0;
    // configure GPIO with the given settings
    gpio_config(&io_conf);

    // disable interrupt
    io_conf.intr_type = GPIO_PIN_INTR_DISABLE;
    // set as input mode
    io_conf.mode = GPIO_MODE_INPUT;
    // bit mask of the pins that you want to set,e.g.GPIO18/19
    io_conf.pin_bit_mask = (1 << 0);
    // disable pull-down mode
    io_conf.pull_down_en = 0;
    // disable pull-up mode
    io_conf.pull_up_en = 1;
    // configure GPIO with the given settings
    gpio_config(&io_conf);
}

static void set_actuator(int st) {
    gpio_set_level(23, st);
}

static int get_reset_button() {
    return gpio_get_level(0);
}

void app_main(void) {
    char chbuf[65];

    ESP_LOGI(LOG_TAG, "Starting virkey...");
    session.sem = xSemaphoreCreateMutex();
    xSemaphoreGive(session.sem);
    setup_gpio();
    ESP_ERROR_CHECK(init_flash());
    ESP_ERROR_CHECK(load_flash_config());
    bin2b64(config.master_key, sizeof(config.master_key), chbuf, sizeof(chbuf));
    ESP_LOGI(LOG_TAG, "master key: %s", chbuf); // Debug only, remove for production!!

    ESP_ERROR_CHECK(init_gatts(connect_cb, disconnect_cb, cmd_cb, config.key_version));

    while(1) {
        vTaskDelay(100 / portTICK_PERIOD_MS);
        while(!xSemaphoreTake(session.sem, portMAX_DELAY))
            ;
        if(act0_tm > 0) {
            act0_tm--;
        }
        set_actuator(act0_tm > 0 ? 1 : 0);

        if(get_reset_button() == 0) {
            ESP_LOGI(LOG_TAG, "Reset button!!!!");
            act0_tm = DEF_ACT_TIMEOUT;
            reset_tm = DEF_ACT_TIMEOUT + 1;
            erase_on_reset = true;
        }

        if(reset_tm > 0) {
            reset_tm--;
            if(!reset_tm) {
                if(erase_on_reset) {
                    reset_flash_config();
                }
                esp_restart();
            }
        }

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
