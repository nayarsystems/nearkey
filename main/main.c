#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "driver/gpio.h"
#include "esp_bt_defs.h"
#include "esp_bt_device.h"
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
#include "boards.h"

#define LOG_TAG "MAIN"

// Boards config
static int const act_tout[] = ACTUATORS_TOUT;
static int const act_gpio[] = ACTUATORS_GPIO;
#define MAX_ACTUATORS (sizeof(act_gpio) / sizeof(act_gpio[0]))
// --- End Boards config

// Errors
#define ERR_OLD_KEY_VERSION 1
#define ERR_OLD_KEY_VERSION_S "Old Key version"
#define ERR_PERMISSION_DENIED 2
#define ERR_PERMISSION_DENIED_S "Permission denied"
#define ERR_UNKNOWN_COMMAND 3
#define ERR_UNKNOWN_COMMAND_S "Unknown command"
// --- End Errors

// Function declarations
static esp_err_t save_flash_config();
static void set_actuator(int act, int st);
static esp_err_t save_access_data();
static uint32_t get_access_data(uint32_t idx);
static int set_access_data(uint32_t idx, uint32_t ts);
static void clear_session(uint16_t conn);
// --- End Function definitions

// Config stuff
#define CFG_VERSION 3
#define MAX_ACCESS_ENTRIES 1024

static struct config_s {
    uint32_t cfg_version;
    uint32_t cfg_setup;
    uint8_t master_key[32];
} __attribute__((packed)) config;

static bool access_chg;
static uint32_t access_blk;
static uint32_t access[MAX_ACCESS_ENTRIES];
static nvs_handle nvs_config_h;
// --- End Config stuff

// Session stuff
#define DEF_SIGNATURE_SIZE 32
#define RX_BUFFER_SIZE 2048
#define DEF_CONN_TIMEOUT 100
SemaphoreHandle_t session_sem;

typedef struct session_s {
    uint16_t gatts_if;
    uint32_t key_version;
    uint32_t key_id;
    uint8_t derived_key[32];
    uint32_t rx_buffer_pos;
    char rx_buffer[RX_BUFFER_SIZE];
    cJSON* login_obj;
    uint64_t nonce;
    uint64_t rnonce;
    uint8_t address[6];
    int conn_timeout;
    bool connected;
    bool login;
    bool upgrade_on_bye;
} session_t ;
static session_t session[CONFIG_BT_ACL_CONNECTIONS];
// --- End Session stuff

// Actuator timers
static int32_t act_timers[MAX_ACTUATORS];
// --- End Actuator timers

// Reset timer
static uint32_t reset_tm;
static bool erase_on_reset;
// --- End Reset timer

// Reset button timer
#define RESET_BUTTON_TIME 30 // 3 seconds
static uint32_t reset_button_tm;
// --- End Reset button timer

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

static int respond(uint16_t conn, cJSON* resp, bool add_nounce, bool add_signature) {
    int res = 0;
    char* json_str = NULL;
    char* sign_str = NULL;
    char* res_str = NULL;
    uint8_t sign_bin[32];
    char nonce_str[32];
    mbedtls_sha256_context sha256_ctx = {};
    size_t olen = 0;

    // Append n and x nonce fields
    if(add_nounce) {
        snprintf(nonce_str, sizeof(nonce_str), "%llu", session[conn].nonce);
        cJSON_AddStringToObject(resp, "n", nonce_str);
    }
    json_str = cJSON_PrintUnformatted(resp);
    if(json_str == NULL) {
        ESP_LOGE("RESPOND", "[%d] Fail encoding JSON data", conn);
        res = 1;
        goto exitfn;
    }
    if(add_signature) {
        // Compute signature
        snprintf(nonce_str, sizeof(nonce_str), "%llu", session[conn].rnonce);
        session[conn].rnonce++; // Increment rnonce for next response
        mbedtls_sha256_init(&sha256_ctx);
        mbedtls_sha256_starts(&sha256_ctx, 0);
        mbedtls_sha256_update(&sha256_ctx, (uint8_t*)json_str, strlen(json_str));
        mbedtls_sha256_update(&sha256_ctx, (uint8_t*)nonce_str, strlen(nonce_str));
        mbedtls_sha256_update(&sha256_ctx, session[conn].derived_key, sizeof(session[conn].derived_key));
        mbedtls_sha256_finish(&sha256_ctx, sign_bin);
        mbedtls_sha256_free(&sha256_ctx);
        mbedtls_base64_encode(NULL, 0, &olen, sign_bin, sizeof(sign_bin));
        sign_str = calloc(1, olen + 1);
        if(sign_str == NULL) {
            res = 1;
            goto exitfn;
        }
        mbedtls_base64_encode((uint8_t*)sign_str, olen, &olen, sign_bin, DEF_SIGNATURE_SIZE);
        asprintf(&res_str, "%s~%s\n", json_str, sign_str);
    } else {
        asprintf(&res_str, "%s\n", json_str);
    }
    gatts_send_response(conn, session[conn].gatts_if, res_str);
    ESP_LOGI("RESPOND", "[%d] Raw response: %s", conn, res_str);

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

static int cmp_perm(const char *perm, const char *cmd){
    int ret = 0;

    for(int n = 0;;n++){
        if (perm[n] == '*' || (perm[n] == 0 && cmd[n] == 0)) {
            ret = 0;
            break;
        }
        if (perm[n] != cmd[n]) {
            ret = 1;
            break;
        }
    }
    return ret;
}

static int chk_cmd_access(uint16_t conn, const char* cmd) {
    int ret = 0;
    int cmdl_size = 0;

    cJSON* cmd_list = NULL;
    cJSON* cmd_entry = NULL;

    cmd_list = cJSON_GetObjectItem(session[conn].login_obj, "a");
    if(cmd_list == NULL) {
        ESP_LOGW("CMD", "[%d] There isn't command access list, all commands denied by default", conn);
        ret = 1;
        goto exitfn;
    }
    if(!(cmd_list->type & cJSON_Array)) {
        ESP_LOGE("CMD", "[%d] Access login is not array type", conn);
        ret = 1;
        goto exitfn;
    }
    cmdl_size = cJSON_GetArraySize(cmd_list);
    for(int cmd_idx = 0; cmd_idx < cmdl_size; cmd_idx++) {
        cmd_entry = cJSON_GetArrayItem(cmd_list, cmd_idx);
        if(cmd_entry == NULL) {
            ESP_LOGE("CMD", "[%d] Unexpexted end of command array", conn);
            ret = 1;
            goto exitfn;
        }
        if(cmd_entry->type == cJSON_String) {
            if (cmp_perm(cmd_entry->valuestring, cmd) == 0) {
                ret = 0;
                goto exitfn;
            }
        }
    }
    ret = 1;

exitfn:
    return ret;
}

static int do_init_config(uint16_t conn, const char* cmd) {
    int ret = 0;
    size_t olen;
    cJSON* json_obj = NULL;
    cJSON* json_item = NULL;
    cJSON* json_resp = NULL;

    json_obj = cJSON_Parse(cmd);
    if(json_obj == NULL) {
        ESP_LOGE("CONFIG", "[%d] Invalid json data", conn);
        ret = 1;
        goto exitfn;
    }
    if(!(json_obj->type & cJSON_Object)) {
        ESP_LOGE("CONFIG", "[%d] JSON login is not object type", conn);
        ret = 1;
        goto exitfn;
    }
    json_item = cJSON_GetObjectItem(json_obj, "t");
    if(json_item == NULL) {
        ESP_LOGE("CONFIG", "[%d] Login object hasn't [t] entry", conn);
        ret = 1;
        goto exitfn;
    }
    if(!(json_item->type & cJSON_String)) {
        ESP_LOGE("CONFIG", "[%d] JSON entry [t] isn't string type", conn);
        ret = 1;
        goto exitfn;
    }
    if(strcmp(json_item->valuestring, "c") != 0) {
        ESP_LOGE("CONFIG", "[%d] Command must be \"c\" type", conn);
        ret = 1;
        goto exitfn;
    }
    json_item = cJSON_GetObjectItem(json_obj, "m");
    if(json_item == NULL) {
        ESP_LOGE("CONFIG", "[%d] config command hasn't [m] entry", conn);
        ret = 1;
        goto exitfn;
    }
    if(!(json_item->type & cJSON_String)) {
        ESP_LOGE("CONFIG", "[%d] JSON entry [m] isn't string type", conn);
        ret = 1;
        goto exitfn;
    }
    if(mbedtls_base64_decode(config.master_key, sizeof(config.master_key), &olen, (uint8_t*)json_item->valuestring,
                             strlen(json_item->valuestring)) != 0) {
        ESP_LOGE("CONFIG", "[%d] Error decoding master key.", conn);
        ret = 1;
        goto exitfn;
    }
    if(olen != sizeof(config.master_key)) {
        ESP_LOGE("CONFIG", "[%d] Master key size mismatch: %d != %d", conn, olen, sizeof(config.master_key));
        ret = 1;
        goto exitfn;
    }
    config.cfg_setup = 1;
    save_flash_config();
    reset_tm = 2;

    json_resp = cJSON_CreateObject();
    cJSON_AddStringToObject(json_resp, "r", "ok");
    cJSON_AddNumberToObject(json_resp, "a", MAX_ACTUATORS);
    cJSON_AddNumberToObject(json_resp, "u", MAX_ACCESS_ENTRIES);
    session[conn].conn_timeout = 5;
    ret = 1;

exitfn:
    if(json_obj != NULL) {
        cJSON_Delete(json_obj);
    }
    if(json_resp != NULL) {
        if(respond(conn, json_resp, false, false) != 0) {
            ESP_LOGE("CONFIG", "[%d] Fail sending response", conn);
            ret = 1;
        }
        cJSON_Delete(json_resp);
    }

    return ret;
}

static int do_login(uint16_t conn, const char* cmd) {
    int ret = 0;
    str_list *sl = NULL, *pl = NULL;
    mbedtls_sha256_context sha256_ctx = {};
    char chbuf[128];
    char* json_data;
    char* sign_data;
    char* nonce_data;
    cJSON* json_item = NULL;
    cJSON* json_resp = NULL;
    uint8_t lmac[6];
    const uint8_t* mac;
    size_t olen;
    uint8_t sig_calc[32] = {0};
    uint8_t sig_peer[32] = {0};

    sl = pl = str_split_safe(cmd, "~");
    if(str_list_len(sl) != 3) {
        ESP_LOGE("LOGIN", "[%d] Invalid login data (split login_data/signature/nonce)", conn);
        ret = 1;
        goto exitfn;
    }

    json_data = pl->s;
    pl = pl->next;
    sign_data = pl->s;
    pl = pl->next;
    nonce_data = pl->s;

    ESP_LOGI("LOGIN", "[%d] Command: %s", conn, json_data);

    // Check login signature
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, (uint8_t*)json_data, strlen(json_data));
    mbedtls_sha256_update(&sha256_ctx, (uint8_t*)"virkey.com", 10);
    mbedtls_sha256_update(&sha256_ctx, config.master_key, sizeof(config.master_key));
    mbedtls_sha256_finish(&sha256_ctx, sig_calc);
    mbedtls_sha256_free(&sha256_ctx);
    olen = sizeof(sig_peer);
    if(mbedtls_base64_decode(sig_peer, olen, &olen, (uint8_t*)sign_data, strlen(sign_data)) != 0) {
        ESP_LOGE("LOGIN", "[%d] Invalid b64 signature", conn);
        ret = 1;
        goto exitfn;
    }
    if(olen != sizeof(sig_peer)) {
        ESP_LOGE("LOGIN", "[%d] Signature length error", conn);
        ret = 1;
        goto exitfn;
    }
    if(memcmp(sig_calc, sig_peer, olen) != 0) {
        ESP_LOGE("LOGIN", "[%d] Signature don't match", conn);
        ret = 1;
        goto exitfn;
    }

    // Set Session rnonce
    session[conn].rnonce = strtoull(nonce_data, NULL, 10);

    // Decode json_data
    SETPTR_cJSON(session[conn].login_obj, cJSON_Parse(json_data));
    if(session[conn].login_obj == NULL) {
        ESP_LOGE("LOGIN", "[%d] Invalid json data", conn);
        ret = 1;
        goto exitfn;
    }
    if(!(session[conn].login_obj->type & cJSON_Object)) {
        ESP_LOGE("LOGIN", "[%d] JSON login is not object type", conn);
        ret = 1;
        goto exitfn;
    }
    json_item = cJSON_GetObjectItem(session[conn].login_obj, "t");
    if(json_item == NULL) {
        ESP_LOGE("LOGIN", "[%d] Login object hasn't [t] entry", conn);
        ret = 1;
        goto exitfn;
    }
    if(!(json_item->type & cJSON_String)) {
        ESP_LOGE("LOGIN", "[%d] JSON entry [t] isn't string type", conn);
        ret = 1;
        goto exitfn;
    }
    if(strcmp(json_item->valuestring, "l") != 0) {
        ESP_LOGE("LOGIN", "[%d] First command must be \"l\" type", conn);
        ret = 1;
        goto exitfn;
    }
    json_item = cJSON_GetObjectItem(session[conn].login_obj, "l");
    if(json_item == NULL) {
        ESP_LOGE("LOGIN", "[%d] Login object hasn't [l] entry", conn);
        ret = 1;
        goto exitfn;
    }
    if(!(json_item->type & cJSON_String)) {
        ESP_LOGE("LOGIN", "[%d] JSON entry [l] isn't string type", conn);
        ret = 1;
        goto exitfn;
    }
    // Check login mac
    olen = sizeof(lmac);
    if(mbedtls_base64_decode(lmac, olen, &olen, (uint8_t*)json_item->valuestring, strlen(json_item->valuestring)) !=
       0) {
        ESP_LOGE("LOGIN", "[%d] Error decoding MAC address", conn);
        ret = 1;
        goto exitfn;
    }
    if(olen != 6) {
        ESP_LOGE("CMD", "[%d] MAC address size isn't 6 bytes long", conn);
        ret = 1;
        goto exitfn;
    }
    mac = esp_bt_dev_get_address();
    if(mac == NULL) {
        ESP_LOGE("CMD", "[%d] Unable to read bluetooth MAC address", conn);
        ret = 1;
        goto exitfn;
    }
    if(memcmp(lmac, mac, 6) != 0) {
        ESP_LOGE("CMD", "[%d] MAC address don't match", conn);
        ret = 1;
        goto exitfn;
    }

    json_item = cJSON_GetObjectItem(session[conn].login_obj, "v");
    if(json_item == NULL) {
        ESP_LOGE("LOGIN", "[%d] Login object hasn't [v] entry", conn);
        ret = 1;
        goto exitfn;
    }
    if(!(json_item->type & cJSON_Number)) {
        ESP_LOGE("LOGIN", "[%d] JSON entry [v] isn't number type", conn);
        ret = 1;
        goto exitfn;
    }
    session[conn].key_version = json_item->valueint;

    json_item = cJSON_GetObjectItem(session[conn].login_obj, "u");
    if(json_item == NULL) {
        ESP_LOGE("LOGIN", "[%d] Login object hasn't [u] entry", conn);
        ret = 1;
        goto exitfn;
    }
    if(!(json_item->type & cJSON_Number)) {
        ESP_LOGE("LOGIN", "[%d] JSON entry [u] isn't number type", conn);
        ret = 1;
        goto exitfn;
    }
    session[conn].key_id = json_item->valueint;

    // Calculate derived key
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, (uint8_t*)sl->s, strlen(json_data));
    mbedtls_sha256_update(&sha256_ctx, sig_calc, sizeof(sig_calc));
    mbedtls_sha256_update(&sha256_ctx, config.master_key, sizeof(config.master_key));
    mbedtls_sha256_finish(&sha256_ctx, session[conn].derived_key);
    mbedtls_sha256_free(&sha256_ctx);
    bin2b64(session[conn].derived_key, sizeof(session[conn].derived_key), chbuf, sizeof(chbuf));
    ESP_LOGI("LOGIN", "[%d] Derived key: %s", conn, chbuf);

    json_resp = cJSON_CreateObject();
    // Check key validity 
    if (set_access_data(session[conn].key_id, session[conn].key_version) < 0){
        cJSON_AddNumberToObject(json_resp, "e", ERR_OLD_KEY_VERSION);
        cJSON_AddStringToObject(json_resp, "d", ERR_OLD_KEY_VERSION_S);
        ret = 1;
        goto exitfn;
    }

    cJSON_AddStringToObject(json_resp, "r", "ok");
    session[conn].login = true;

exitfn:
    if(sl != NULL) {
        str_list_free(sl);
    }
    if(json_resp != NULL) {
        if(respond(conn, json_resp, true, true) != 0) {
            ESP_LOGE("LOGIN", "[%d] Fail sending response", conn);
            ret = 1;
        }
        cJSON_Delete(json_resp);
    }

    return ret;
}

static int do_cmd_key_upgrade(uint16_t conn, const char* cmd, cJSON* json_resp){
    int ret = 0;
    cJSON* login_obj = NULL;
    cJSON* json_item = NULL;
    char* login_JSON_str = NULL;
    char* login_b64_str = NULL;
    char* login_sig_str = NULL;
    char* login_dkey_str = NULL;
    mbedtls_sha256_context sha256_ctx = {};
    uint8_t sig_calc[32] = {0};
    size_t olen = 0;

    login_obj = cJSON_Duplicate(session[conn].login_obj, 1);
    json_item = cJSON_GetObjectItem(login_obj, "v");
    json_item->valueint++;
    json_item->valuedouble++;

    // Remove "u" from permissions
    cJSON* cmd_list = NULL;
    cJSON* cmd_entry = NULL;
    int cmdl_size;
    cmd_list = cJSON_GetObjectItem(login_obj, "a");
    if(cmd_list == NULL) {
        ESP_LOGW("CMD_UPGRADE", "[%d] There isn't command access list, all commands denied by default", conn);
        ret = 1;
        goto exitfn;
    }
    if(!(cmd_list->type & cJSON_Array)) {
        ESP_LOGE("CMD_UPGRADE", "[%d] Access login is not array type", conn);
        ret = 1;
        goto exitfn;
    }
    cmdl_size = cJSON_GetArraySize(cmd_list);
    for(int cmd_idx = 0; cmd_idx < cmdl_size; cmd_idx++) {
        cmd_entry = cJSON_GetArrayItem(cmd_list, cmd_idx);
        if(cmd_entry == NULL) {
            ESP_LOGE("CMD_UPGRADE", "[%d] Unexpexted end of command array", conn);
            ret = 1;
            goto exitfn;
        }
        if(cmd_entry->type == cJSON_String) {
            if(strcmp("u", cmd_entry->valuestring) == 0) {
                cJSON_DeleteItemFromArray(cmd_list, cmd_idx);
                break;
            }
        }
    }


    login_JSON_str = cJSON_PrintUnformatted(login_obj);
    // Calculate login signature
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, (uint8_t*)login_JSON_str, strlen(login_JSON_str));
    mbedtls_sha256_update(&sha256_ctx, (uint8_t*)"virkey.com", 10);
    mbedtls_sha256_update(&sha256_ctx, config.master_key, sizeof(config.master_key));
    mbedtls_sha256_finish(&sha256_ctx, sig_calc);
    mbedtls_sha256_free(&sha256_ctx);

    mbedtls_base64_encode(NULL, 0, &olen, sig_calc, sizeof(sig_calc));
    login_sig_str = calloc(1, olen + 1);
    if(login_sig_str == NULL) {
        ret = 1;
        goto exitfn;
    }
    mbedtls_base64_encode((uint8_t*)login_sig_str, olen, &olen, sig_calc, sizeof(sig_calc));

    // Calculate derived key
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, (uint8_t*)login_JSON_str, strlen(login_JSON_str));
    mbedtls_sha256_update(&sha256_ctx, sig_calc, sizeof(sig_calc));
    mbedtls_sha256_update(&sha256_ctx, config.master_key, sizeof(config.master_key));
    mbedtls_sha256_finish(&sha256_ctx, sig_calc);
    mbedtls_sha256_free(&sha256_ctx);

    // Encrypt derived key with session derived key
    for(int i = 0; i < sizeof(sig_calc); i++){
        sig_calc[i] = sig_calc[i] ^ session[conn].derived_key[i];
    }

    mbedtls_base64_encode(NULL, 0, &olen, sig_calc, sizeof(sig_calc));
    login_dkey_str = calloc(1, olen + 1);
    if(login_dkey_str == NULL) {
        ret = 1;
        goto exitfn;
    }
    mbedtls_base64_encode((uint8_t*)login_dkey_str, olen, &olen, sig_calc, sizeof(sig_calc));

    // Convert login JSON data to base64
    mbedtls_base64_encode(NULL, 0, &olen, (uint8_t*)login_JSON_str, strlen(login_JSON_str));
    login_b64_str = calloc(1, olen + 1);
    if(login_b64_str == NULL) {
        ret = 1;
        goto exitfn;
    }
    mbedtls_base64_encode((uint8_t*)login_b64_str, olen, &olen, (uint8_t*)login_JSON_str, strlen(login_JSON_str));

    
    cJSON *robject = cJSON_CreateObject();
    cJSON_AddStringToObject(robject, "login", login_b64_str);
    cJSON_AddStringToObject(robject, "sig", login_sig_str);
    cJSON_AddStringToObject(robject, "dkey", login_dkey_str);
    cJSON_AddItemToObject(json_resp, "r", robject);

    session[conn].upgrade_on_bye = true;


exitfn:
    if(login_JSON_str != NULL) {
        free(login_JSON_str);
    }
    if(login_b64_str != NULL) {
        free(login_b64_str);
    }
    if(login_sig_str != NULL) {
        free(login_sig_str);
    }
    if(login_dkey_str != NULL) {
        free(login_dkey_str);
    }
    if(login_obj != NULL) {
        cJSON_Delete(login_obj);
    }
    return ret;
}

static int do_cmd(uint16_t conn, const char* cmd) {
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


    sl = pl = str_split_safe(cmd, "~");
    if(str_list_len(sl) != 2) {
        ESP_LOGE("CMD", "[%d] Invalid command data (split data/signature)", conn);
        ret = 1;
        goto exitfn;
    }

    json_data = pl->s;
    pl = pl->next;
    sign_data = pl->s;

    // Calculate signature
    snprintf(nonce_str, sizeof(nonce_str), "%llu", session[conn].nonce);
    session[conn].nonce++; // Increment nonce for next command
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, (uint8_t*)json_data, strlen(json_data));
    mbedtls_sha256_update(&sha256_ctx, (uint8_t*)nonce_str, strlen(nonce_str));
    mbedtls_sha256_update(&sha256_ctx, session[conn].derived_key, sizeof(session[conn].derived_key));
    mbedtls_sha256_finish(&sha256_ctx, sig_calc);
    mbedtls_sha256_free(&sha256_ctx);

    // Check signature
    olen = sizeof(sig_peer);
    if(mbedtls_base64_decode(sig_peer, olen, &olen, (uint8_t*)sign_data, strlen(sign_data)) != 0) {
        ESP_LOGE("CMD", "[%d] Invalid b64 signature", conn);
        ret = 1;
        goto exitfn;
    }
    if(olen < 16) {
        ESP_LOGE("CMD", "[%d] Signature too short (%d)", conn, olen);
        ret = 1;
        goto exitfn;
    }
    if(memcmp(sig_calc, sig_peer, olen) != 0) {
        ESP_LOGE("CMD", "[%d] Signature don't match", conn);
        ret = 1;
        goto exitfn;
    }

    // Decode json data
    json_cmd = cJSON_Parse(json_data);
    if(json_cmd == NULL) {
        ESP_LOGE("CMD", "[%d] Malformed JSON data", conn);
        ret = 1;
        goto exitfn;
    }
    if(!(json_cmd->type & cJSON_Object)) {
        ESP_LOGE("CMD", "[%d] JSON is not object type", conn);
        ret = 1;
        goto exitfn;
    }
    json_item = cJSON_GetObjectItem(json_cmd, "t");
    if(json_item == NULL) {
        ESP_LOGE("CMD", "[%d] Cmd object hasn't [t] entry", conn);
        ret = 1;
        goto exitfn;
    }
    if(!(json_item->type & cJSON_String)) {
        ESP_LOGE("CMD", "[%d] Entry [t] isn't string type", conn);
        ret = 1;
        goto exitfn;
    }
    cmd_str = json_item->valuestring;

    json_resp = cJSON_CreateObject();
    if(strcmp(cmd_str, "q") == 0) { // Quit
        if (session[conn].upgrade_on_bye) {
            session[conn].upgrade_on_bye = false;
            set_access_data(session[conn].key_id, get_access_data(session[conn].key_id) + 1);
        }
        ret = 1;
        goto exitok;
    }

    if(strcmp(cmd_str, "n") == 0) { // Nop
        ret = 0;
        goto exitok;
    }

    if(chk_cmd_access(conn, cmd_str) != 0) {
        cJSON_AddNumberToObject(json_resp, "e", ERR_PERMISSION_DENIED);
        cJSON_AddStringToObject(json_resp, "d", ERR_PERMISSION_DENIED_S);
        ret = 0;
        goto exitfn;
    }

    if(strlen(cmd_str) >= 2 && cmd_str[0] == 'a' && cmd_str[1] >= '0' && cmd_str[1] <= '9') { // Actuator
        int n = atoi(&cmd_str[1]);
        if(n >= 0 && n < MAX_ACTUATORS) {
            if(act_tout[n] < 0 && act_timers[n] < 0){
                act_timers[n] = 0;
            } else {
                act_timers[n] = act_tout[n];
            }
            ESP_LOGI("CMD", "[%d] shoting actuator %d", conn, n);
        } else {
            ESP_LOGE("CMD", "[%d] actuator %d out of range", conn, n);
        }
        ret = 0;
        goto exitok;
    }

    if (strcmp(cmd_str, "u") == 0 || strcmp(cmd_str, "U") == 0){
        ret = do_cmd_key_upgrade(conn, cmd, json_resp);
        goto exitfn;
    }

    cJSON_AddNumberToObject(json_resp, "e", ERR_UNKNOWN_COMMAND);
    cJSON_AddStringToObject(json_resp, "d", ERR_UNKNOWN_COMMAND_S);
    ret = 0;
    goto exitfn;

exitok:
    cJSON_AddStringToObject(json_resp, "r", "ok");
exitfn:
    if(sl != NULL) {
        str_list_free(sl);
    }
    if(json_cmd != NULL) {
        cJSON_Delete(json_cmd);
    }
    if(json_resp != NULL) {
        if(respond(conn, json_resp, false, true) != 0) {
            ESP_LOGE("LOGIN", "[%d] Fail sending response", conn);
            ret = 1;
        }
        cJSON_Delete(json_resp);
    }
    return ret;
}

static void clear_session(uint16_t conn){
    SETPTR_cJSON(session[conn].login_obj, NULL); // Free login JSON data
    memset(&session[conn], 0, sizeof(session_t));
    save_access_data();
}

static int connect_cb(uint16_t conn, uint16_t gatts_if, const esp_bd_addr_t addr) {
    int ret = 0;

    while(!xSemaphoreTake(session_sem, portMAX_DELAY))
        ;
    clear_session(conn);
    memcpy(&session[conn].address, addr, sizeof(((session_t *)0)->address));
    session[conn].gatts_if = gatts_if;
    session[conn].conn_timeout = DEF_CONN_TIMEOUT;
    session[conn].connected = true;
    session[conn].nonce = esp_random();
    ESP_LOGI(LOG_TAG, "[%d] Connection from: %02x:%02x:%02x:%02x:%02x:%02x", conn, session[conn].address[0], session[conn].address[1],
             session[conn].address[2], session[conn].address[3], session[conn].address[4], session[conn].address[5]);
    gatts_start_adv();
    xSemaphoreGive(session_sem);
    return ret;
}

static int disconnect_cb(uint16_t conn) {
    int ret = 0;

    while(!xSemaphoreTake(session_sem, portMAX_DELAY))
        ;
    ESP_LOGI(LOG_TAG, "[%d] Disconnected from: %02x:%02x:%02x:%02x:%02x:%02x", conn, session[conn].address[0], session[conn].address[1],
             session[conn].address[2], session[conn].address[3], session[conn].address[4], session[conn].address[5]);
    clear_session(conn);
    ESP_LOGI(LOG_TAG,"Free heap size: %d", esp_get_free_heap_size());
    xSemaphoreGive(session_sem);
    return ret;
}

static int cmd_cb(uint16_t conn) {
    int ret = 0;

    ESP_LOGI(LOG_TAG, "[%d] Command: %s", conn, session[conn].rx_buffer);
    if(!session[conn].login) {
        if(config.cfg_setup == 0) {
            ret = do_init_config(conn, session[conn].rx_buffer);
        } else {
            ret = do_login(conn, session[conn].rx_buffer);
        }
    } else {
        ret = do_cmd(conn, session[conn].rx_buffer);
    }
    if(ret != 0) {
        session[conn].login = false; // Logout on unrecoverable error
        if(session[conn].conn_timeout > 5){
            session[conn].conn_timeout = 5; // Set timeout to 500ms (allow last response to be sent and close)
        }
    } else {
        session[conn].conn_timeout = DEF_CONN_TIMEOUT; // Reload timeout on command success 
    }
    return 0;
}

static int rx_cb(uint16_t conn, const uint8_t *data, size_t data_len) {
    int retval = 0;

    while(!xSemaphoreTake(session_sem, portMAX_DELAY));
    if(!session[conn].connected) {
        retval = 1;
        goto exitfn;
    }
    if (session[conn].rx_buffer_pos + data_len > (RX_BUFFER_SIZE - 2)){
        retval = 1;
        ESP_LOGE(LOG_TAG, "[%d] RX buffer overflow", conn);
        goto exitfn;
    }
    memcpy(&session[conn].rx_buffer[session[conn].rx_buffer_pos], data, data_len);
    session[conn].rx_buffer_pos += data_len;
    session[conn].rx_buffer[session[conn].rx_buffer_pos] = 0;

    char* end_cmd = strchr(session[conn].rx_buffer, 10); // Search for "\n"
    if(end_cmd != NULL) {
        *end_cmd = '\0';
        cmd_cb(conn);
        session[conn].rx_buffer_pos = 0;
        session[conn].rx_buffer[0] = 0;
    }

exitfn:    
    xSemaphoreGive(session_sem);
    return retval;
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
        if (err != ESP_OK){
            goto fail;
        }
    }
fail:
    return err;
}

static esp_err_t load_access_data(){
    esp_err_t err = ESP_OK;

    access_chg = false;
    err = nvs_get_u32(nvs_config_h, "access_blk", &access_blk);
    if(err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "Error (%d) reading nvs access_blk", err);
        goto fail;
    }
    const esp_partition_t* part = esp_partition_find_first(0x40, ESP_PARTITION_SUBTYPE_ANY, NULL);
    if (part == NULL){
        ESP_LOGE(LOG_TAG, "Error, access partition not found");
        err = ESP_ERR_NVS_NOT_FOUND;
        goto fail;
    }
    err = esp_partition_read(part, sizeof(access) * access_blk, access, sizeof(access));
    if (err != ESP_OK){
        ESP_LOGE(LOG_TAG, "Error (%d) writing access data partition", err);
        goto fail;
    }
    ESP_LOGI(LOG_TAG, "acces data loaded from block: %d", access_blk);

fail:
    return err;
}

static esp_err_t save_access_data() {
    esp_err_t err = ESP_OK;

    if (access_chg){
        const esp_partition_t* part = esp_partition_find_first(0x40, ESP_PARTITION_SUBTYPE_ANY, NULL);
        if (part == NULL){
            ESP_LOGE(LOG_TAG, "Error, access partition not found");
            err = ESP_ERR_NVS_NOT_FOUND;
            goto fail;
        }
        access_blk += 1;
        if (access_blk * sizeof(access) >= part->size) {
            access_blk = 0;
        }
        err = esp_partition_erase_range(part, sizeof(access) * access_blk, sizeof(access));
        if (err != ESP_OK){
            ESP_LOGE(LOG_TAG, "Error (%d) erasing access data partition", err);
            goto fail;
        }
        err = esp_partition_write(part, sizeof(access) * access_blk, access, sizeof(access));
        if (err != ESP_OK){
            ESP_LOGE(LOG_TAG, "Error (%d) writing access data partition", err);
            goto fail;
        }

        // Save access blk
        err = nvs_set_u32(nvs_config_h, "access_blk", access_blk);
        if (err != ESP_OK){
            ESP_LOGE(LOG_TAG, "Error (%d) writing access_blk data", err);
            goto fail;
        }
        err = nvs_commit(nvs_config_h);
        if(err != ESP_OK){
            ESP_LOGE(LOG_TAG, "Error (%d) writing access_blk data (commit)", err);
            goto fail;
        }
        access_chg = false;
        ESP_LOGI(LOG_TAG, "acces data written to block: %d", access_blk);
    }

fail:
    return err;
}


static uint32_t get_access_data(uint32_t idx){
    
    assert(idx < MAX_ACCESS_ENTRIES);
    return access[idx];
}

static int set_access_data(uint32_t idx, uint32_t ts){
    int ret = -1;

    if (idx >= MAX_ACCESS_ENTRIES) {
        ret = -1;
    } else if (access[idx] == ts){
        ret = 0;
    } else if (access[idx] < ts){
        access[idx] = ts;
        access_chg = true;
        ret = 1;
    }
    return ret;
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
    // Reset main config
    memset(&config, 0, sizeof(config));
    config.cfg_version = CFG_VERSION;
    config.cfg_setup = 0;
    memset(config.master_key, 0, sizeof(config.master_key));
    err = save_flash_config();
    if(err != ESP_OK){
        goto fail;
    }
    memset(access, 0, sizeof(access));
    access_blk = 0;
    access_chg = true;
    err = save_access_data();
    if(err != ESP_OK){
        goto fail;
    }

fail:
    return err;
}

static esp_err_t load_flash_config() {
    esp_err_t err = ESP_OK;
    
    err = nvs_open("virkey", NVS_READWRITE, &nvs_config_h);
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
    gpio_config_t io_conf = {0};

    // bit mask of the pins that you want to set as outputs
    for(int n = 0; n < MAX_ACTUATORS; n++) {
        if (act_gpio[n] < 0){
            continue;
        }
        io_conf.pin_bit_mask |= ((uint64_t)1 << act_gpio[n]);
    }
#if STATUS_LED_GPIO >= 0    
    io_conf.pin_bit_mask |= ((uint64_t)1 << STATUS_LED_GPIO);
#endif    
    // disable interrupt
    io_conf.intr_type = GPIO_PIN_INTR_DISABLE;
    // set as output mode
    io_conf.mode = GPIO_MODE_OUTPUT;
    // disable pull-down mode
    io_conf.pull_down_en = 0;
    // disable pull-up mode
    io_conf.pull_up_en = 0;
    // configure GPIO with the given settings
    gpio_config(&io_conf);

    
    if (RESET_BUTTON_GPIO >= 0){
        io_conf = (gpio_config_t){0};
        // disable interrupt
        io_conf.intr_type = GPIO_PIN_INTR_DISABLE;
        // set as input mode
        io_conf.mode = GPIO_MODE_INPUT;
        // bit mask of the pins that you want to set as inputs
        // io_conf.pin_bit_mask = (1 << 0);
        io_conf.pin_bit_mask = ((uint64_t)1 << RESET_BUTTON_GPIO);
        // disable pull-down mode
        io_conf.pull_down_en = 0;
        // disable pull-up mode
        io_conf.pull_up_en = 0;
        // configure GPIO with the given settings
        gpio_config(&io_conf);
    }
    reset_button_tm = RESET_BUTTON_TIME;
}


static void set_status_led(int st) {
#if STATUS_LED_GPIO >= 0
    gpio_set_level(STATUS_LED_GPIO, st);
#endif
}

static void set_actuator(int act, int st) {
    if(act >= 0 && act < MAX_ACTUATORS) {
        if (act_gpio[act] >= 0 && act_gpio[act] < GPIO_NUM_MAX) {
            gpio_set_level(act_gpio[act], st);
        }
    }
}

static int get_reset_button() {
#if RESET_BUTTON_GPIO >=0    
    return gpio_get_level(RESET_BUTTON_GPIO);
#else
    return 1
#endif
}

void app_main(void) {
    char chbuf[65];
    bool status_led = false;
    
    ESP_LOGI(LOG_TAG, "Starting virkey...");
    session_sem = xSemaphoreCreateMutex();
    xSemaphoreGive(session_sem);
    setup_gpio();
    ESP_ERROR_CHECK(init_flash());
    ESP_ERROR_CHECK(load_flash_config());
    ESP_ERROR_CHECK(load_access_data());
    bin2b64(config.master_key, sizeof(config.master_key), chbuf, sizeof(chbuf));
    ESP_LOGI(LOG_TAG, "master key: %s", chbuf); // Debug only, remove for production!!

    ESP_ERROR_CHECK(init_gatts(connect_cb, disconnect_cb, rx_cb, config.cfg_setup));

    while(1) {
        vTaskDelay(100 / portTICK_PERIOD_MS);
        while(!xSemaphoreTake(session_sem, portMAX_DELAY));

        // Update actuators
        for (int act = 0; act < MAX_ACTUATORS; act ++){
            set_actuator(act, act_timers[act] != 0);
            if(act_timers[act] > 0){
                act_timers[act]--;
            }
        }
        // --- End Update actuators
        
        // Close connections on timeout
        for (int conn = 0; conn < CONFIG_BT_ACL_CONNECTIONS; conn ++){
            if(session[conn].connected){
                if(session[conn].conn_timeout > 0){
                    session[conn].conn_timeout --;
                    if(!session[conn].conn_timeout){
                        gatts_close_connection(conn, session[conn].gatts_if);
                        ESP_LOGI(LOG_TAG, "[%d] session wdt timeout", conn);
                    }
                }
            }
        }
        // --- End Close connections on timeout

        // Reset Button
        if (get_reset_button() == 0) {
            if (reset_button_tm > 0) {
                reset_button_tm --;
                ESP_LOGW(LOG_TAG, "Reset button [%u]", reset_button_tm);
            }
        } else {
            if (reset_button_tm > 0) {
                reset_button_tm = RESET_BUTTON_TIME;
            } else {
                reset_tm = 1;
                erase_on_reset = true;
            }
        }
        // --- End Reset Button

        // Status LED
        if (get_reset_button() == 0 && reset_button_tm > 0){ // LED On
            status_led = true;
        } else if ((get_reset_button() == 0 && reset_button_tm == 0) || (config.cfg_setup == 0)) { // LED Blink
            status_led = !status_led;
        } else {
            status_led = false;
        }
        set_status_led(status_led);
        // --- End Status LED

        // Reset timer
        if(reset_tm > 0) {
            reset_tm--;
            if(!reset_tm) {
                if(erase_on_reset) {
                    reset_flash_config();
                }
                esp_restart();
            }
        }
        // --- End Reset Timer

        xSemaphoreGive(session_sem);
    }
}