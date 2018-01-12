#define CA_PK "wGuvDFUQLiTeUp2o5VlVbK6+8lP+UMVeClxpQ6RpkAA="
#define FW_VER 16
#define PRODUCT "VIRKEY"
#define LOG_TAG "MAIN"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sodium.h"
#include "cwpack.h"
#include "driver/gpio.h"
#include "driver/i2c.h"
#include "esp_bt_defs.h"
#include "esp_bt_device.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "esp_deep_sleep.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "gatts.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_ota_ops.h"
#include "parseutils.h"
#include "utils.h"
#include "boards.h"
#include "hwrtc.h"

// Magic info
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
static const char magic[] = "vkfwmark:" "{\"bo\":\"" HW_BOARD "\",\"pr\":\"" PRODUCT "\",\"fv\":" STR(FW_VER) "}";
//

// Boards config
static int const act_tout[] = ACTUATORS_TOUT;
static int const act_gpio[] = ACTUATORS_GPIO;
#define MAX_ACTUATORS (sizeof(act_gpio) / sizeof(act_gpio[0]))
// --- End Boards config

// Errors
#define ERR_INTERNAL            1
#define ERR_APP_ERROR           2

#define ERR_FRAME_UNKNOWN       100
#define ERR_FRAME_INVALID       101
#define ERR_CRYPTO_SIGNATURE    102

#define ERR_OLD_KEY_VERSION     200
#define ERR_PERMISSION_DENIED   201
#define ERR_KEY_EXPIRED         202
#define ERR_TIME_RESTRICTION    203

#define ERR_UNKNOWN_COMMAND     300
#define ERR_INVALID_PARAMS      301
#define ERR_NOT_LOGGED          302 

#define ERR_FLASH_LOCKED        900
#define ERR_FLASH_NOTOWNED      901
#define ERR_FLASH_OTAINIT       902
#define ERR_FLASH_OUTDATED      903
#define ERR_FLASH_PARTERROR     904
#define ERR_FLASH_OVERRUN       905
#define ERR_FLASH_CHECKSUM      906
#define ERR_FLASH_BOOT          907
#define ERR_FLASH_BOARD         908
#define ERR_FLASH_PRODUCT       909


typedef struct _code {
    int code;
	char *desc;
} CODE;

static CODE errors[] = {
    {ERR_INTERNAL, "Internal error"},
    {ERR_APP_ERROR, "Application level error"},
    {ERR_FRAME_UNKNOWN, "Unknown frame type"},
    {ERR_FRAME_INVALID, "Invalid frame data"},
    {ERR_CRYPTO_SIGNATURE, "Invalid signature"},
    {ERR_OLD_KEY_VERSION , "Old Key version"},
    {ERR_PERMISSION_DENIED, "Permission denied"},
    {ERR_UNKNOWN_COMMAND, "Unknown command"},
    {ERR_INVALID_PARAMS, "Invalid params"},
    {ERR_KEY_EXPIRED, "Key expired"},
    {ERR_TIME_RESTRICTION, "Access denied due to temporary restriction rules"},
    {ERR_FLASH_LOCKED, "Flash Locked"},
    {ERR_FLASH_NOTOWNED, "Flash not owned"},
    {ERR_FLASH_OTAINIT, "OTA not initialized"},
    {ERR_FLASH_OUTDATED, "Outdated firmware"},
    {ERR_FLASH_PARTERROR, "Partition error"},
    {ERR_FLASH_OVERRUN, "Flash overrun"},
    {ERR_FLASH_CHECKSUM, "Flash checksum fail"},
    {ERR_FLASH_BOOT, "Error setting boot partition"},
    {ERR_FLASH_BOARD, "Incompatible board firmware"},
    {ERR_FLASH_PRODUCT, "Incompatible product firmware"},
    {-1, NULL},
};

// --- End Errors

// Log stuff
#define LOG_SIZE 20
#define LOG_FIELDS 6

#define LOG_OP_BOOT      1
#define LOG_OP_TIME_SET  10
#define LOG_OP_FW_INIT   20
#define LOG_OP_FW_END    21
#define LOG_OP_ACTUATOR  100

static CODE log_ops[] = {
    {LOG_OP_BOOT, "Boot"},
    {LOG_OP_TIME_SET, "Time set"},
    {LOG_OP_FW_INIT, "Firmware flash init"},
    {LOG_OP_FW_END, "Firmware flash end"},
    {LOG_OP_ACTUATOR, "Shot actuator"},
    {-1, NULL},
};

typedef struct log_s {
    uint32_t cnt;
    int32_t usr;
    int32_t ts;
    int32_t op;
    int32_t par;
    int32_t res;
} log_t;
static int32_t log_cnt;
static int32_t log_idx;
static log_t log[LOG_SIZE];
// -- End Log stuff

// Config stuff
static struct config_s {
    uint32_t cfg_version;
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t secret_key[crypto_box_SECRETKEYBYTES];
    uint8_t ca_key[crypto_box_PUBLICKEYBYTES];
    uint8_t vk_id[6];
    uint64_t key_ver;
    uint32_t boot_cnt; 
    char tz[64];
    char tzn[64];
} __attribute__((packed)) config;

static nvs_handle nvs_config_h;
static uint8_t ca_shared[crypto_box_BEFORENMBYTES];
// --- End Config stuff

// Session stuff
#define EGG_OVERHEAD crypto_box_NONCEBYTES + crypto_box_MACBYTES
#define SEED_SIZE 16
#define RX_BUFFER_SIZE 2048
#define TX_BUFFER_SIZE 1024
#define RESP_BUFFER_SIZE TX_BUFFER_SIZE - 32
#define DEF_CONN_TIMEOUT 300
SemaphoreHandle_t session_sem;

typedef struct session_s {
    uint16_t h;
    time_t creation_ts;
    uint16_t gatts_if;
    int32_t  user;
    uint32_t key_version;
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    uint8_t seed[SEED_SIZE];
    uint8_t nonce[32];
    uint8_t rnonce[32];
    size_t rx_buffer_len;
    uint8_t *rx_buffer;
    uint8_t *tx_buffer;
    uint8_t *resp_buffer;
    uint8_t *login_data;
    cw_pack_context pc_tx;
    cw_pack_context pc_resp;
    size_t login_len;
    uint8_t address[6];
    int conn_timeout;
    bool connected;
    bool blocked;
    bool login;
    bool ota_lock;
} session_t ;
static session_t session[CONFIG_BT_ACL_CONNECTIONS];
// --- End Session stuff

// OTA stuff
typedef struct ota_s {
    bool start;
    bool ota_end;
    uint32_t started_update;
    uint8_t sha256sum[32];
    mbedtls_sha256_context sha256_ctx;
    esp_ota_handle_t handle;
    const esp_partition_t *part;
    size_t size;
    size_t offset;
} ota_t;
static ota_t ota;
static bool ota_lock;
// --- End OTA stuff

// Time restrictions
typedef struct time_res_s {
    uint8_t dow;
    uint32_t dom;
    uint16_t mon;
    uint8_t n_ran;
    uint32_t ran[10];
} __attribute__((packed)) time_res_t;
// --- End Time restrictions 

// Egg stuff
typedef struct egg_header_s {
    uint8_t id[6];
    uint32_t boot_cnt;
    uint32_t egg_cnt;
    uint8_t padding[10];
} __attribute__((packed)) egg_header_t;
static uint32_t egg_cnt;
// --- End Egg stuff

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

// Function declarations
static int reset_flash_config(bool);
static esp_err_t save_flash_config();
static void set_actuator(int act, int st);
static void clear_session(session_t *s);
static int chk_expiration(session_t *s);
static int chk_time_res(session_t *s, const char *field, bool nreq);
// --- End Function definitions



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


static const char *code2str(CODE *map, int code) {
    for (int idx =0; map[idx].code != -1; idx++) {
        if (map[idx].code == code){
            return map[idx].desc;
        }
    }
    return "";
}

static void cw_pack_cstr(cw_pack_context *pc, const char *str) {
    cw_pack_str(pc, str, strlen(str));
}

static void msgpack_restore(cw_unpack_context *upc){
    upc->item.type = CWP_NOT_AN_ITEM;
    upc->current = upc->start;
    upc->return_code = CWP_RC_OK;
    upc->err_no = 0;
}

static char *msgpack_cstr(cw_unpack_context *upc, char *buff, size_t bsize) {
    memset(buff, 0, bsize);
    size_t sz = upc->item.as.str.length;
    if (sz > bsize - 1) {
        sz = bsize - 1;
    }
    strncpy(buff, upc->item.as.str.start, sz);
    return buff;
}

static int msgpack_cmp_str(cw_unpack_context *upc, const char *str){
    if (upc->item.type != CWP_ITEM_STR) return -1;
    if (upc->item.as.str.length != strlen(str)) return -1;
    if (strncmp(upc->item.as.str.start, str, upc->item.as.str.length) != 0) return -1;
    return 0;
}

static int msgpack_map_search(cw_unpack_context *upc, const char *key){
    cw_unpack_next(upc);
    if (upc->return_code != CWP_RC_OK || upc->item.type != CWP_ITEM_MAP) return -1;
    for (uint32_t ms = upc->item.as.map.size; ms > 0 ; ms --) {
        cw_unpack_next(upc);
        if (upc->return_code != CWP_RC_OK || upc->item.type != CWP_ITEM_STR) return -1;
        if (msgpack_cmp_str(upc, key) == 0) return 0;
        cw_skip_items(upc, 1); // Skip value item
    }
    return -1;
}

static char *nctime_r(const time_t *timep, char *buf){
    char *ret = ctime_r(timep, buf);
    size_t l = strlen(buf);
    if (l > 0) buf[l-1] = 0; // Remove nasty LF 
    return ret;
}

void print_current_time(void) {
    char chbuf[64];
    
    time_t now = time(NULL);
    ESP_LOGI(LOG_TAG, "Current time: %s", nctime_r(&now, chbuf));
}

static bool chk_time() {
    return time(NULL) > 1483225200L; // check if date is greater than 2017/01/01 00:00:00
}

static void reboot(){
    esp_deep_sleep(1000LL * 10); // 10ms
}

static void bin2b64(const uint8_t* buf, size_t sz, char* dst, size_t dst_sz) {
    mbedtls_base64_encode((uint8_t*)dst, dst_sz, &dst_sz, buf, sz);
    dst[dst_sz] = 0;
}

static void log_add(session_t *s, int32_t op, int32_t par, int32_t res) {
    int32_t usr = -1;
    int32_t sh = -1; 
    int32_t now = time(NULL);

    if (s != NULL) {
        usr = s->user;
        sh = s->h;
    }
    log_cnt++;
    log[log_idx].cnt = log_cnt;
    log[log_idx].usr = usr;
    log[log_idx].ts =  now;
    log[log_idx].op = op;
    log[log_idx].par = par;
    log[log_idx].res = res;
    log_idx++;
    if (log_idx >= LOG_SIZE) {
        log_idx = 0;
    }
    ESP_LOGI("LOGGER","[%d] cnt:%d usr:%d ts:%d op:%d opd:\"%s\" par:%d res:%d", sh, log_cnt, usr, now, op, code2str(log_ops, op), par, res);
}

static int respond(session_t *s) {
    size_t sz = s->pc_tx.current - s->pc_tx.start;
    gatts_send_response(s->h, s->gatts_if, s->pc_tx.start, sz);
    ESP_LOGI("RESPOND", "[%d] Send response [sz:%d]", s->h, sz);
    return 0;
}

static void inc_nonce(uint8_t *nonce) {
    for (int n = crypto_box_NONCEBYTES - 1; n >= 0; n-- ) {
        if ((++nonce[n]) != 0) {
            break;
        }
    }
}

static void encrypt_response(session_t *s, const char *t, bool seed) {
    size_t sz = s->pc_resp.current - s->pc_resp.start;
    uint8_t *enc_data = malloc(sz + crypto_box_MACBYTES);

    crypto_box_easy_afternm(enc_data, s->pc_resp.start, sz, s->rnonce, s->shared_key);
    inc_nonce(s->rnonce);
    if (seed) {
        cw_pack_map_size(&s->pc_tx, 3);    
    } else {
        cw_pack_map_size(&s->pc_tx, 2);    
    }
    cw_pack_cstr(&s->pc_tx, "t"); cw_pack_cstr(&s->pc_tx, t);
    cw_pack_cstr(&s->pc_tx, "d"); cw_pack_bin(&s->pc_tx, enc_data, sz + crypto_box_MACBYTES);
    if (seed) {
        cw_pack_cstr(&s->pc_tx, "n"); cw_pack_bin(&s->pc_tx, s->seed, SEED_SIZE);
    }
    free(enc_data);
    return;
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

static int chk_cmd_access(session_t *s, const char* cmd) {
    int err = 0;
    char str_buf[32];
    cw_unpack_context upc;

    if (!chk_time()) { // On clock failure allow only "ts" command
        if(strcmp(cmd, "ts") == 0) {
            err = 0;
            goto exitfn;
        }
        err = ERR_PERMISSION_DENIED;
        goto exitfn;
    } else {
        if (chk_expiration(s) != 0) {
            err = ERR_KEY_EXPIRED;
            goto exitfn;
        }
        if (chk_time_res(s, "y", true) != 0 ){
            err = ERR_TIME_RESTRICTION;
            goto exitfn;
        }

        if (chk_time_res(s, "z", false) == 0 ){
            err = ERR_TIME_RESTRICTION;
            goto exitfn;
        }
    }

    cw_unpack_context_init(&upc, s->login_data, s->login_len, NULL);
    int r = msgpack_map_search(&upc, "a");
    if (r){
        ESP_LOGE("CMD", "[%d] There isn't command access list, all commands denied by default", s->h);
        err = ERR_INTERNAL;
        goto exitfn;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_ARRAY) {
        ESP_LOGE("CMD", "[%d] Access list isn't array type", s->h);
        err = ERR_INTERNAL;
        goto exitfn;
    }
    for(int i = upc.item.as.array.size; i > 0; i--) {
        cw_unpack_next(&upc);
        if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_STR) {
            ESP_LOGE("CMD", "[%d] Access entry isn't string type", s->h);
            err = ERR_INTERNAL;
            goto exitfn;
        }
        msgpack_cstr(&upc, str_buf, sizeof(str_buf));
        if (cmp_perm(str_buf, cmd) == 0) {
            goto exitfn;
        }
    }
    err = ERR_PERMISSION_DENIED;
exitfn:
    return err;
}
 

static int chk_time_res_buf(const uint8_t *buf, size_t sz){
    time_res_t tr = {0};
    int ret = 0;

    if (sz > sizeof(tr)){
        sz = sizeof(tr);
    }
    memcpy(&tr, buf, sz);

    time_t now = time(NULL);
    struct tm ltm;
    if (localtime_r(&now, &ltm) == NULL){
        ret = -1;
        goto exitfn;
    }
    // Check day of week
    if (!(tr.dow & ((uint8_t)1 << ltm.tm_wday))){
        ret = 1;
        goto exitfn;
    }
    // Check day of month
    if (!(tr.dom & ((uint32_t)1 << (ltm.tm_mday - 1)))){
        ret = 1;
        goto exitfn;
    }
    // Check month
    if (!(tr.mon & ((uint16_t)1 << ltm.tm_mon))){
        ret = 1;
        goto exitfn;
    }
    // Check minute ranges of day 
    int min = ltm.tm_hour * 60 + ltm.tm_min;
    for(int n = 0; n < tr.n_ran; n++){
        if(min >= (tr.ran[n] & 0xffff) && min <= (tr.ran[n] >> 16)){
            ret = 0;
            goto exitfn;
        }
        ret = 1;
    }
 
exitfn:
    return ret;
}

static int chk_time_res(session_t *s, const char *field, bool nreq) {
    int ret = 0;
    cw_unpack_context upc;

    cw_unpack_context_init(&upc, s->login_data, s->login_len, NULL);
    int r = msgpack_map_search(&upc, field);
    if (r){
        if (nreq) {
            ret = 0;
        } else {
            ret = 1;
        }
        goto exitfn;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_ARRAY) {
        ESP_LOGE("CHK_TIME_RES", "[%d] Time restrictions field is not array type", s->h);
        ret = 2;
        goto exitfn;
    }
    for(int i = upc.item.as.array.size; i > 0; i--) {
        cw_unpack_next(&upc);
        if (upc.return_code != CWP_RC_OK || (upc.item.type != CWP_ITEM_STR && upc.item.type != CWP_ITEM_BIN)) {
            ESP_LOGE("CHK_TIME_RES", "[%d] Restriction isn't str/bin type", s->h);
            ret = 2;
            goto exitfn;
        }
        if(chk_time_res_buf(upc.item.as.bin.start, upc.item.as.bin.length) == 0) {
            ret = 0;
            goto exitfn;
        }
    }
    ret = 1;
exitfn:
    return ret;
}

static int chk_expiration(session_t *s) {
    int ret = 0;
    cw_unpack_context upc;

    cw_unpack_context_init(&upc, s->login_data, s->login_len, NULL);
    int r = msgpack_map_search(&upc, "x");
    if (r){
        ret = 0;
        goto exitfn;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_ARRAY) {
        ESP_LOGE("CHK_EXPIRATION", "[%d] Expiration field is not array type", s->h);
        ret = 2;
        goto exitfn;
    }
    if(upc.item.as.array.size != 2) {
        ESP_LOGE("CHK_EXPIRATION", "[%d] Expiration array size missmatch", s->h);
        ret = 2;
        goto exitfn;
    }
    time_t now = time(NULL);
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_POSITIVE_INTEGER) {
        ESP_LOGE("CHK_EXPIRATION", "[%d] Invalid array element type", s->h);
        ret = 2;
        goto exitfn;
    }
    if (now < upc.item.as.u64) {
        ESP_LOGE("CHK_EXPIRATION", "[%d] Time before valid range.", s->h);
        ret = -1;
        goto exitfn;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_POSITIVE_INTEGER) {
        ESP_LOGE("CHK_EXPIRATION", "[%d] Invalid array element type", s->h);
        ret = 2;
        goto exitfn;
    }
    if (now > upc.item.as.u64) {
        ESP_LOGE("CHK_EXPIRATION", "[%d] Time before valid range.", s->h);
        ret = -1;
        goto exitfn;
    }
exitfn:
    return ret;
}

static int append_egg(session_t *s, cw_pack_context *out) {
    int ret = 0;
    cw_pack_context pc;
    uint8_t *blob = malloc(1024 + EGG_OVERHEAD);
    
    if (blob == NULL) {
        ret = -1;
        goto exitfn;
    }
    size_t map_size = 9; 
    if (ota.start) {
        map_size += 5;
    }
    cw_pack_context_init(&pc, &blob[EGG_OVERHEAD], 1024, NULL);
    cw_pack_map_size(&pc, map_size);
    cw_pack_cstr(&pc, "t"); cw_pack_cstr(&pc, "sta");
    cw_pack_cstr(&pc, "fv"); cw_pack_unsigned(&pc, FW_VER);
    cw_pack_cstr(&pc, "kv"); cw_pack_unsigned(&pc, config.key_ver);
    cw_pack_cstr(&pc, "bo"); cw_pack_cstr(&pc, HW_BOARD);
    cw_pack_cstr(&pc, "pr"); cw_pack_cstr(&pc, PRODUCT);
    cw_pack_cstr(&pc, "tz"); cw_pack_cstr(&pc, config.tz);
    cw_pack_cstr(&pc, "tn"); cw_pack_cstr(&pc, config.tzn);
    cw_pack_cstr(&pc, "ts"); cw_pack_unsigned(&pc, time(NULL));
    cw_pack_cstr(&pc, "lg"); cw_pack_array_size(&pc, LOG_SIZE);
    for(int n = 0; n < LOG_SIZE; n++) {
        cw_pack_array_size(&pc, LOG_FIELDS);
        cw_pack_unsigned(&pc, log[n].cnt);
        cw_pack_signed(&pc, log[n].usr);
        cw_pack_signed(&pc, log[n].ts);
        cw_pack_signed(&pc, log[n].op);
        cw_pack_signed(&pc, log[n].par);
        cw_pack_signed(&pc, log[n].res);
    }
    if (ota.start) {
        cw_pack_cstr(&pc, "st"); cw_pack_boolean(&pc, ota.start);
        cw_pack_cstr(&pc, "ha"); cw_pack_bin(&pc, ota.sha256sum, sizeof(ota.sha256sum));
        cw_pack_cstr(&pc, "uv"); cw_pack_unsigned(&pc, ota.started_update);
        cw_pack_cstr(&pc, "sz"); cw_pack_unsigned(&pc, ota.size);
        cw_pack_cstr(&pc, "of"); cw_pack_unsigned(&pc, ota.offset);
    }


    size_t mlen = pc.current - pc.start;
    egg_header_t *h = (egg_header_t *)blob;
    memcpy(&h->id, config.vk_id, sizeof(h->id));
    egg_cnt++;
    if (egg_cnt == 0) { // egg_cnt overflow
        config.boot_cnt++;
        egg_cnt = 1;
        ESP_ERROR_CHECK(save_flash_config());
    }
    h->boot_cnt = config.boot_cnt;
    h->egg_cnt = egg_cnt;
    randombytes_buf(&h->padding, sizeof(h->padding));
    crypto_box_easy_afternm(&blob[crypto_box_NONCEBYTES], &blob[EGG_OVERHEAD], mlen, blob, ca_shared);

    cw_pack_cstr(out, "egg");
    cw_pack_bin(out, blob, mlen + EGG_OVERHEAD);

    exitfn:
    if (blob != NULL) {
        free(blob);
    }
    return ret;
}

static int process_login_frame(session_t *s) {
    int ret = 0, err = 0;
    cw_unpack_context upc;

    cw_unpack_context_init(&upc, s->rx_buffer, s->rx_buffer_len, NULL);
    int r = msgpack_map_search(&upc, "d");
    if (r){
        ESP_LOGE("LOGIN", "[%d] Error obtaining encrypted blob: %d", s->h, r);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || (upc.item.type != CWP_ITEM_STR && upc.item.type != CWP_ITEM_BIN)) {
        ESP_LOGE("LOGIN", "[%d] Invalid type for encrypted blob", s->h);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    if ( upc.item.as.bin.length <= (crypto_box_NONCEBYTES + crypto_box_MACBYTES + 64)) {
        ESP_LOGE("LOGIN", "[%d] encrypted blob too short", s->h);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    size_t blob_sz = upc.item.as.bin.length - (crypto_box_NONCEBYTES + crypto_box_MACBYTES);
    SETPTR(s->login_data, malloc(blob_sz));
    s->login_len = blob_sz;
    if (crypto_box_open_easy_afternm(s->login_data,
            upc.item.as.bin.start + crypto_box_NONCEBYTES,
            upc.item.as.bin.length - crypto_box_NONCEBYTES,
            upc.item.as.bin.start,
            ca_shared) != 0) {
        ESP_LOGE("LOGIN", "[%d] Invalid signature", s->h);
        ret = ERR_CRYPTO_SIGNATURE;
        goto exitfn;
    }
    msgpack_restore(&upc);
    r = msgpack_map_search(&upc, "n");
    if (r){
        ESP_LOGE("LOGIN", "[%d] Error obtaining nonce seed: %d", s->h, r);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || (upc.item.type != CWP_ITEM_STR && upc.item.type != CWP_ITEM_BIN)) {
        ESP_LOGE("LOGIN", "[%d] Invalid type for nonce seed", s->h);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    if ( upc.item.as.bin.length < 16) {
        ESP_LOGE("LOGIN", "[%d] Invalid nonce seed size", s->h);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    // calc nonces
    randombytes_buf(s->seed, SEED_SIZE);
    mbedtls_sha256_context sha256_ctx;

    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, upc.item.as.bin.start, upc.item.as.bin.length);
    mbedtls_sha256_update(&sha256_ctx, s->seed, SEED_SIZE);
    mbedtls_sha256_finish(&sha256_ctx, s->rnonce);
    mbedtls_sha256_free(&sha256_ctx);

    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, s->seed, SEED_SIZE);
    mbedtls_sha256_update(&sha256_ctx, upc.item.as.bin.start, upc.item.as.bin.length);
    mbedtls_sha256_finish(&sha256_ctx, s->nonce);
    mbedtls_sha256_free(&sha256_ctx);

    // Process Login data
    cw_unpack_context_init(&upc, s->login_data, s->login_len, NULL);
    r = msgpack_map_search(&upc, "t");
    if (r){
        ESP_LOGE("LOGIN", "[%d] \"t\" field  not present: %d", s->h, r);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_STR) {
        ESP_LOGE("LOGIN", "[%d] Invalid \"t\" field type", s->h);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    if (msgpack_cmp_str(&upc, "l") != 0) {
        ESP_LOGE("LOGIN", "[%d] command is not \"l\"", s->h);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }

    msgpack_restore(&upc);
    r = msgpack_map_search(&upc, "u");
    if (r) {
        ESP_LOGE("LOGIN", "[%d] \"u\" field not present: %d", s->h, r);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || (upc.item.type != CWP_ITEM_POSITIVE_INTEGER && upc.item.type != CWP_ITEM_NEGATIVE_INTEGER)) {
        ESP_LOGE("LOGIN", "[%d] Invalid \"u\" field type", s->h);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    s->user = upc.item.as.i64;
    ESP_LOGI("LOGIN", "[%d] User: %d", s->h, s->user);
    
    msgpack_restore(&upc);
    r = msgpack_map_search(&upc, "uk");
    if (r){
        ESP_LOGE("LOGIN", "[%d] \"uk\" field not present: %d", s->h, r);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || (upc.item.type != CWP_ITEM_STR && upc.item.type != CWP_ITEM_BIN)) {
        ESP_LOGE("LOGIN", "[%d] Invalid \"uk\" field type", s->h);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    if ( upc.item.as.bin.length != crypto_box_PUBLICKEYBYTES) {
        ESP_LOGE("LOGIN", "[%d] Invalid \"uk\" field size", s->h);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    if(crypto_box_beforenm(s->shared_key, upc.item.as.bin.start, config.secret_key) != 0) {
        ESP_LOGE("LOGIN", "Error computing user shared key");
        ret = ERR_APP_ERROR;
        goto exitfn;
    }

    msgpack_restore(&upc);
    r = msgpack_map_search(&upc, "i");
    if (r){
        ESP_LOGE("LOGIN", "[%d] \"i\" field not present: %d", s->h, r);
        err = ERR_FRAME_INVALID;
        goto exitfn;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || (upc.item.type != CWP_ITEM_STR && upc.item.type != CWP_ITEM_BIN)) {
        ESP_LOGE("LOGIN", "[%d] Invalid \"i\" field type", s->h);
        err = ERR_FRAME_INVALID;
        goto exitfn;
    }
    if ( upc.item.as.bin.length != sizeof(config.vk_id)) {
        ESP_LOGE("LOGIN", "[%d] Invalid \"i\" field size", s->h);
        err = ERR_FRAME_INVALID;
        goto exitfn;
    }
    if(memcmp(config.vk_id, upc.item.as.bin.start, sizeof(config.vk_id)) != 0) {
        ESP_LOGE("LOGIN", "[%d] \"i\" field don't match", s->h);
        err = ERR_FRAME_INVALID;
        goto exitfn;
    }

    msgpack_restore(&upc);
    r = msgpack_map_search(&upc, "v");
    if (r){
        ESP_LOGE("LOGIN", "[%d] \"v\" field not present: %d", s->h, r);
        err = ERR_FRAME_INVALID;
        goto exitfn;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_POSITIVE_INTEGER) {
        ESP_LOGE("LOGIN", "[%d] Invalid type for \"v\" field", s->h);
        err = ERR_FRAME_INVALID;
        goto exitfn;
    }
    if (upc.item.as.u64 < config.key_ver) {
        err = ERR_OLD_KEY_VERSION;
        goto exitfn;
    }
    if (upc.item.as.u64 > config.key_ver) {
        config.key_ver = upc.item.as.u64;
        save_flash_config();
        ESP_LOGI("LOGIN", "[%d] Updated key to version:%llu", s->h, config.key_ver);
    }

    if(chk_time()){
        if (chk_expiration(s) != 0) {
            err = ERR_KEY_EXPIRED;
            goto exitfn;
        }
    } else {
        ESP_LOGE("LOGIN", "[%d] clock out of time. Only \"ts\" command allowed", s->h);
    }

    s->login = true;
    cw_pack_map_size(&s->pc_resp, 3);
    cw_pack_cstr(&s->pc_resp, "fv"); cw_pack_unsigned(&s->pc_resp, FW_VER);
    cw_pack_cstr(&s->pc_resp, "bo"); cw_pack_cstr(&s->pc_resp, HW_BOARD);
    cw_pack_cstr(&s->pc_resp, "ts"); cw_pack_unsigned(&s->pc_resp, time(NULL));

exitfn:
    if (ret > 0) {
        return ret;
    }
    if (err > 0) {
        cw_pack_map_size(&s->pc_resp, 2);
        cw_pack_cstr(&s->pc_resp, "e"); cw_pack_signed(&s->pc_resp, err);
        cw_pack_cstr(&s->pc_resp, "d"); cw_pack_cstr(&s->pc_resp, code2str(errors, err));
        ESP_LOGE("LOGIN", "[%d] Login error: (%d) %s", s->h, err, code2str(errors, err));
    }
    encrypt_response(s, "rl", true);
    return ret;
}

static int do_cmd_ts(session_t *s){
    int ret = 0;
    struct timeval tv={0};
    bool conf_save = false;
    char str[64];
    cw_unpack_context upc;

    cw_unpack_context_init(&upc, s->rx_buffer, s->rx_buffer_len, NULL);
    int r = msgpack_map_search(&upc, "ts");
    if (r == 0){
        cw_unpack_next(&upc);
        if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_POSITIVE_INTEGER) {
            ESP_LOGE("CMD", "[%d] Entry \"ts\" isn't positive integer type", s->h);
            ret = ERR_INVALID_PARAMS;
            goto exitfn;
        }
        tv.tv_sec = (time_t) upc.item.as.u64;
        settimeofday(&tv, NULL);
        ESP_LOGI("CMD", "[%d] Timestamp set to: %llu", s->h, upc.item.as.u64)

#ifdef RTC_DRIVER
        systohc();
#endif
    }

    msgpack_restore(&upc);
    r = msgpack_map_search(&upc, "tz");
    if (r == 0) {
        cw_unpack_next(&upc);
        if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_STR) {
            ESP_LOGE("CMD", "[%d] Entry \"tz\" isn't string type", s->h);
            ret = ERR_INVALID_PARAMS;
            goto exitfn;
        }
        msgpack_cstr(&upc, str, sizeof(str));
        if (strcmp(config.tz, str) != 0){
            strlcpy(config.tz, str, sizeof(config.tz));
            setenv("TZ", config.tz, 1);
            tzset();
            ESP_LOGI("CMD", "[%d] Time zone posix string set to: %s", s->h, config.tz)
            conf_save = true;
        }
    }

    msgpack_restore(&upc);
    r = msgpack_map_search(&upc, "tzn");
    if (r == 0) {
        cw_unpack_next(&upc);
        if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_STR) {
            ESP_LOGE("CMD", "[%d] Entry \"tzn\" isn't string type", s->h);
            ret = ERR_INVALID_PARAMS;
            goto exitfn;
        }
        msgpack_cstr(&upc, str, sizeof(str));
        if (strcmp(config.tzn, str) != 0){
            strlcpy(config.tzn, msgpack_cstr(&upc, str, sizeof(str)), sizeof(config.tzn));
            ESP_LOGI("CMD", "[%d] Time zone name string set to: %s", s->h, config.tzn)
            conf_save = true;
        }
    }

    if (conf_save) {
        save_flash_config();
    }
    
    cw_pack_map_size(&s->pc_resp, 3);
    cw_pack_cstr(&s->pc_resp, "tz"); cw_pack_cstr(&s->pc_resp, config.tz);
    cw_pack_cstr(&s->pc_resp, "tn"); cw_pack_cstr(&s->pc_resp, config.tzn);
    cw_pack_cstr(&s->pc_resp, "ts"); cw_pack_unsigned(&s->pc_resp, time(NULL));
    print_current_time(); 
exitfn:
    return ret;
}

static void reset_ota() {
    if (ota.start) { // Free resources for started OTA
        mbedtls_sha256_free(&ota.sha256_ctx);
        if (!ota.ota_end){
            esp_ota_end(ota.handle);
        }
    }
    memset(&ota, 0, sizeof(ota));
}

static int do_cmd_fs(session_t *s){
    cw_pack_map_size(&s->pc_resp, 8);
    cw_pack_cstr(&s->pc_resp, "lo"); cw_pack_boolean(&s->pc_resp, ota_lock);
    cw_pack_cstr(&s->pc_resp, "st"); cw_pack_boolean(&s->pc_resp, ota.start);
    cw_pack_cstr(&s->pc_resp, "ha"); cw_pack_bin(&s->pc_resp, ota.sha256sum, sizeof(ota.sha256sum));
    cw_pack_cstr(&s->pc_resp, "bo"); cw_pack_cstr(&s->pc_resp, HW_BOARD);
    cw_pack_cstr(&s->pc_resp, "uv"); cw_pack_unsigned(&s->pc_resp, ota.started_update);
    cw_pack_cstr(&s->pc_resp, "rv"); cw_pack_unsigned(&s->pc_resp, FW_VER);
    cw_pack_cstr(&s->pc_resp, "sz"); cw_pack_unsigned(&s->pc_resp, ota.size);
    cw_pack_cstr(&s->pc_resp, "of"); cw_pack_unsigned(&s->pc_resp, ota.offset);
    return 0;
}

static int do_cmd_fi(session_t *s){
    int err = 0;
    uint32_t update = 0;
    cw_unpack_context upc, back_upc;

    if (ota_lock) {
        err= ERR_FLASH_LOCKED;
        goto exitfn_locked;
    }
    ota_lock = true;
    s->ota_lock = true;

    cw_unpack_context_init(&upc, s->login_data, s->login_len, NULL);
    int r = msgpack_map_search(&upc, "fu");
    if(r) {
        err = ERR_PERMISSION_DENIED;
        goto exitfn_fail;
    }
    back_upc = upc;

    r = msgpack_map_search(&upc, "uv");
    if(r) {
        ESP_LOGE("CMD", "[%d] \"uv\" entry not pressent", s->h);
        err = ERR_INVALID_PARAMS;
        goto exitfn_fail;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_POSITIVE_INTEGER) {
        ESP_LOGE("CMD", "[%d] \"uv\" is not positive integer", s->h);
        err = ERR_INVALID_PARAMS;
        goto exitfn_fail;
    }
    update = upc.item.as.u64;

    upc = back_upc;
    r = msgpack_map_search(&upc, "ha");
    if(r) {
        ESP_LOGE("CMD", "[%d] \"ha\" entry not pressent", s->h);
        err = ERR_INVALID_PARAMS;
        goto exitfn_fail;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || (upc.item.type != CWP_ITEM_BIN && upc.item.type != CWP_ITEM_STR)) {
        ESP_LOGE("CMD", "[%d] \"ha\" is not binary array type", s->h);
        err = ERR_INVALID_PARAMS;
        goto exitfn_fail;
    }
    if (upc.item.as.bin.length != sizeof(ota.sha256sum)) { 
        ESP_LOGE("CMD", "[%d] \"ha\" hash length missmatch", s->h);
        err = ERR_INVALID_PARAMS;
        goto exitfn_fail;
    }
    const uint8_t *hash = upc.item.as.bin.start;

    upc = back_upc;
    r = msgpack_map_search(&upc, "bo");
    if(r) {
        ESP_LOGE("CMD", "[%d] \"bo\" entry not pressent", s->h);
        err = ERR_INVALID_PARAMS;
        goto exitfn_fail;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_STR) {
        ESP_LOGE("CMD", "[%d] \"bo\" is not string type", s->h);
        err = ERR_INVALID_PARAMS;
        goto exitfn_fail;
    }
    char board[64];
    msgpack_cstr(&upc, board, sizeof(board));

    upc = back_upc;
    r = msgpack_map_search(&upc, "pr");
    if(r) {
        ESP_LOGE("CMD", "[%d] \"pr\" entry not pressent", s->h);
        err = ERR_INVALID_PARAMS;
        goto exitfn_fail;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_STR) {
        ESP_LOGE("CMD", "[%d] \"pr\" is not string type", s->h);
        err = ERR_INVALID_PARAMS;
        goto exitfn_fail;
    }
    char product[64];
    msgpack_cstr(&upc, product, sizeof(product));

    upc = back_upc;
    r = msgpack_map_search(&upc, "sz");
    if(r) {
        ESP_LOGE("CMD", "[%d] \"sz\" entry not pressent", s->h);
        err = ERR_INVALID_PARAMS;
        goto exitfn_fail;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_POSITIVE_INTEGER) {
        ESP_LOGE("CMD", "[%d] \"sz\" is not positive integer", s->h);
        err = ERR_INVALID_PARAMS;
        goto exitfn_fail;
    }
    size_t size = upc.item.as.u64;

    if (update <= FW_VER) {
        err = ERR_FLASH_OUTDATED;
        goto exitfn_fail;
    }

    if (strcmp(board, HW_BOARD) != 0) {
        err = ERR_FLASH_BOARD;
        goto exitfn_fail;
    }

    if (strcmp(product, PRODUCT) != 0) {
        err = ERR_FLASH_PRODUCT;
        goto exitfn_fail;
    }

    if (ota.start) {
        if (update < ota.started_update) {
            err = ERR_FLASH_OUTDATED;
            goto exitfn_fail;
        }

        if (update > ota.started_update || ota.size != size || memcmp(hash, ota.sha256sum, sizeof(ota.sha256sum)) != 0) {
            reset_ota();
        }
    }

    // Prepare OTA
    if (!ota.start){ 
        reset_ota();
        memcpy(ota.sha256sum, hash, sizeof(ota.sha256sum));
        ota.offset = 0;
        ota.started_update = update;
        ota.size = size;
        ota.part = esp_ota_get_next_update_partition(NULL);
        if (ota.part == NULL) {
            err = ERR_FLASH_PARTERROR;
            goto exitfn_fail;
        }
        if (esp_ota_begin(ota.part, ota.size, &ota.handle) != ESP_OK) {
            err = ERR_FLASH_PARTERROR;
            goto exitfn_fail;
        }
        mbedtls_sha256_init(&ota.sha256_ctx);
        mbedtls_sha256_starts(&ota.sha256_ctx, 0);
        ota.start = true;
    }
    log_add(s, LOG_OP_FW_INIT, update, 0);
    return do_cmd_fs(s);
exitfn_fail:
    ota_lock = false;
    s->ota_lock = false;
exitfn_locked:
    log_add(s, LOG_OP_FW_INIT, update, err);
    return err;
}

static int do_cmd_fw(session_t *s){
    int err = 0;
    uint32_t update = ota.started_update;
    cw_unpack_context upc;

    if (!s->ota_lock){
        err = ERR_FLASH_NOTOWNED;
        goto exitfn;
    }

    if (!ota.start) {
        err =  ERR_FLASH_OTAINIT;
        goto exitfn;
    }

    cw_unpack_context_init(&upc, s->rx_buffer, s->rx_buffer_len, NULL);
    int r = msgpack_map_search(&upc, "d");
    if (r) {
        ESP_LOGE("CMD", "[%d] \"d\" entry not pressent", s->h);
        err = ERR_INVALID_PARAMS;
        goto exitfn;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || (upc.item.type != CWP_ITEM_BIN && upc.item.type != CWP_ITEM_STR)) {
        ESP_LOGE("CMD", "[%d] \"d\" is not bin/str type", s->h);
        err = ERR_INVALID_PARAMS;
        goto exitfn;
    }

    if (esp_ota_write(ota.handle, upc.item.as.bin.start, upc.item.as.bin.length) != ESP_OK) {
        err = ERR_FLASH_PARTERROR;
        reset_ota();
        goto exitfn;
    }
    mbedtls_sha256_update(&ota.sha256_ctx, upc.item.as.bin.start, upc.item.as.bin.length);
    ota.offset += upc.item.as.bin.length;

    if (ota.offset > ota.size) {
        err = ERR_FLASH_OVERRUN;
        reset_ota();
        goto exitfn;
    }

    if (ota.offset == ota.size) {
        uint8_t chk_calc[32] = {0};
        mbedtls_sha256_finish(&ota.sha256_ctx, chk_calc);
        if(memcmp(chk_calc, ota.sha256sum, sizeof(chk_calc)) == 0) {
            ota.ota_end = true;
            esp_err_t esp_err = esp_ota_end(ota.handle);
            if (esp_err != ESP_OK) {
                err = ERR_FLASH_CHECKSUM;
                reset_ota();
                goto exitfn;
            }    
            esp_err = esp_ota_set_boot_partition(ota.part);
            if (esp_err != ESP_OK) {
                err = ERR_FLASH_BOOT;
                reset_ota();
                goto exitfn;
            }
            log_add(s, LOG_OP_FW_END, update, 0);
            reset_ota();
            reset_tm = 10;
        } else {
            err = ERR_FLASH_CHECKSUM;
            reset_ota();
            goto exitfn;
        }
    }

    cw_pack_map_size(&s->pc_resp, 1);
    cw_pack_cstr(&s->pc_resp, "of"); cw_pack_unsigned(&s->pc_resp, ota.offset);

exitfn:
    if (err != 0) {
        log_add(s, LOG_OP_FW_END, update, err);
    }
    return err;
}

static int process_cmd_frame(session_t *s) {
    int ret = 0, err = 0;
    cw_unpack_context upc;
    char cmd_str[32];

    if (!s->login) {
        ESP_LOGE("CMD", "[%d] Received command on not logged connection", s->h);
        ret = ERR_NOT_LOGGED;
        goto exitfn;
    }

    cw_unpack_context_init(&upc, s->rx_buffer, s->rx_buffer_len, NULL);
    int r = msgpack_map_search(&upc, "d");
    if (r){
        ESP_LOGE("CMD", "[%d] Error obtaining encrypted blob: %d", s->h, r);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || (upc.item.type != CWP_ITEM_STR && upc.item.type != CWP_ITEM_BIN)) {
        ESP_LOGE("CMD", "[%d] Invalid encrypted blob type", s->h);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    const uint8_t *start = upc.item.as.bin.start;
    size_t sz = upc.item.as.bin.length;
    if (crypto_box_open_easy_afternm(s->rx_buffer, //Overwrite rx_buffer
            start,
            sz,
            s->nonce,
            s->shared_key) != 0) {
        ESP_LOGE("LOGIN", "[%d] Invalid signature", s->h);
        ret = ERR_CRYPTO_SIGNATURE;
        goto exitfn;
    }
    s->rx_buffer_len = sz - crypto_box_MACBYTES;
    inc_nonce(s->nonce);

    cw_unpack_context_init(&upc, s->rx_buffer, s->rx_buffer_len, NULL);
    r = msgpack_map_search(&upc, "t");
    if (r){
        ESP_LOGE("CMD", "[%d] Cmd object hasn't \"t\" entry", s->h);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_STR) {
        ESP_LOGE("CMD", "[%d] Entry \"t\" isn't string type", s->h);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    msgpack_cstr(&upc, cmd_str, sizeof(cmd_str));
    ESP_LOGI("CMD","[%d] Command: %s", s->h, cmd_str);

    // [q] command (QUIT)
    if(strcmp(cmd_str, "q") == 0) { // Quit
        s->login = false;
        if (s->ota_lock) {
            s->ota_lock = false;
            ota_lock = false;
        }
        goto exitok;
    }

    // [n] command (NOP)
    if(strcmp(cmd_str, "n") == 0) { // Nop
        goto exitok;
    }

    // [fs] flash get state
    if (strcmp(cmd_str, "fs") == 0){
        err = do_cmd_fs(s);
        goto exitfn;
    }

    // [fi] flash init
    if (strcmp(cmd_str, "fi") == 0){
        err = do_cmd_fi(s);
        goto exitfn;
    }

    // [fw] flash write
    if (strcmp(cmd_str, "fw") == 0){
        err = do_cmd_fw(s);
        goto exitfn;
    }

    err = chk_cmd_access(s, cmd_str);
    if (err != 0) {
        goto exitfn;
    }

    // [a] command (ACTUATOR n)
    if(strlen(cmd_str) >= 2 && cmd_str[0] == 'a' && cmd_str[1] >= '0' && cmd_str[1] <= '9') { // Actuator
        int n = atoi(&cmd_str[1]);
        if(n >= 0 && n < MAX_ACTUATORS) {
            if(act_tout[n] < 0 && act_timers[n] < 0){
                act_timers[n] = 0;
            } else {
                act_timers[n] = act_tout[n];
            }
            ESP_LOGI("CMD", "[%d] shoting actuator %d", s->h, n);
            log_add(s, LOG_OP_ACTUATOR, n, 0);
        } else {
            ESP_LOGE("CMD", "[%d] actuator %d out of range", s->h, n);
        }
        goto exitok;
    }

    // [ts] command (TIME SET/GET)
    if (strcmp(cmd_str, "ts") == 0){
        ret = do_cmd_ts(s);
        log_add(s, LOG_OP_TIME_SET, 0, ret);
        goto exitfn;
    }

    err = ERR_UNKNOWN_COMMAND;
    goto exitfn;

exitok:
    ret = 0;
    err = 0;
    cw_pack_map_size(&s->pc_resp, 1);
    cw_pack_cstr(&s->pc_resp, "r"); cw_pack_cstr(&s->pc_resp, "ok");

exitfn:
    if (ret > 0) {
        return ret;
    }
    if (err > 0) {
        cw_pack_map_size(&s->pc_resp, 2);
        cw_pack_cstr(&s->pc_resp, "e"); cw_pack_signed(&s->pc_resp, err);
        cw_pack_cstr(&s->pc_resp, "d"); cw_pack_cstr(&s->pc_resp, code2str(errors, err));
        ESP_LOGE("CMD", "[%d] command error: (%d) %s", s->h, err, code2str(errors, err));
    }
    encrypt_response(s, "rc", false);
    return ret;
}
 
static void clear_session(session_t *s){
    if (s->ota_lock){
        ota_lock = false;
    }
    SETPTR(s->tx_buffer, NULL);
    SETPTR(s->rx_buffer, NULL);
    SETPTR(s->resp_buffer, NULL);
    SETPTR(s->login_data, NULL);
    memset(s, 0, sizeof(session_t));
}

static bool is_configured(){
    for(int n = 0; n < sizeof(config.vk_id); n++){
        if (config.vk_id[n] != 0){
            return true;
        }
    }
    return false;
}

static int connect_cb(uint16_t conn, uint16_t gatts_if, const esp_bd_addr_t addr) {
    int ret = 0;
    session_t *s = &session[conn];
    while(!xSemaphoreTake(session_sem, portMAX_DELAY));
    clear_session(s);
    memcpy(&s->address, addr, sizeof(((session_t *)0)->address));
    s->h = conn;
    s->gatts_if = gatts_if;
    s->conn_timeout = DEF_CONN_TIMEOUT;
    s->connected = true;
    s->creation_ts = time(NULL);
    SETPTR(s->tx_buffer, malloc(TX_BUFFER_SIZE));
    SETPTR(s->rx_buffer, malloc(RX_BUFFER_SIZE));
    SETPTR(s->resp_buffer, malloc(RESP_BUFFER_SIZE));
    ESP_LOGI(LOG_TAG, "[%d] Connection from: %02x:%02x:%02x:%02x:%02x:%02x", conn, s->address[0], s->address[1],
             s->address[2], s->address[3], s->address[4], s->address[5]);
    gatts_start_adv();
    xSemaphoreGive(session_sem);
    return ret;
}

static int disconnect_cb(uint16_t conn) {
    int ret = 0;
    session_t *s = &session[conn];
    while(!xSemaphoreTake(session_sem, portMAX_DELAY))
        ;
    ESP_LOGI(LOG_TAG, "[%d] Disconnected from: %02x:%02x:%02x:%02x:%02x:%02x", conn, s->address[0], s->address[1],
             s->address[2], s->address[3], s->address[4], s->address[5]);
    clear_session(s);
    ESP_LOGI(LOG_TAG,"Free heap size: %d", esp_get_free_heap_size());
    xSemaphoreGive(session_sem);
    return ret;
}

static int process_info_frame(session_t *s){
    int ret = 0;

    if (!is_configured()){
        reset_flash_config(true);
        ret = -1;
        reset_tm = 10;
    }
    cw_pack_map_size(&s->pc_tx, 4);
    cw_pack_cstr(&s->pc_tx, "t"); cw_pack_cstr(&s->pc_tx, "ri");
    cw_pack_cstr(&s->pc_tx, "pk"); cw_pack_bin(&s->pc_tx, config.public_key, crypto_box_PUBLICKEYBYTES);
    cw_pack_cstr(&s->pc_tx, "ca"); cw_pack_bin(&s->pc_tx, config.ca_key, crypto_box_PUBLICKEYBYTES);
    append_egg(s, &s->pc_tx);
    return ret;
}

static int cmd_cb(session_t *s) {
    int ret = 0;
    char ch_buff[64];

    cw_pack_context_init(&s->pc_resp, s->resp_buffer, RESP_BUFFER_SIZE, NULL); // Init command response context
    cw_pack_context_init(&s->pc_tx, s->tx_buffer, TX_BUFFER_SIZE, NULL); // Init frame response context
    cw_unpack_context upc;
    cw_unpack_context_init(&upc, s->rx_buffer, s->rx_buffer_len, NULL);
    int r = msgpack_map_search(&upc, "t");
    if (r){
        ESP_LOGE(LOG_TAG, "[%d] Error obtaining command type field: %d", s->h, r);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_STR) {
        ESP_LOGE(LOG_TAG, "[%d] command type isn't string type", s->h);
        ret = ERR_FRAME_INVALID;
        goto exitfn;
    }
    ESP_LOGI(LOG_TAG, "[%d] Rx frame: %s", s->h, msgpack_cstr(&upc, ch_buff, sizeof(ch_buff)));

    if (msgpack_cmp_str(&upc, "i") == 0) {
        ret = process_info_frame(s);
    } else if (msgpack_cmp_str(&upc, "l") == 0) {
        ret = process_login_frame(s);
    } else if (msgpack_cmp_str(&upc, "c") == 0) {
        ret = process_cmd_frame(s);
    } else {
        ret = ERR_FRAME_UNKNOWN;
        goto exitfn;
    }

exitfn:    
    if(ret != 0) {
        s->login = false; // Logout on unrecoverable error
        if(s->conn_timeout > 5){
            s->conn_timeout = 5; // Set timeout to 500ms (allow last response to be sent and close)
        }
        s->blocked = true;
        if (ret > 0) {
            cw_pack_context_init(&s->pc_tx, s->tx_buffer, TX_BUFFER_SIZE, NULL); // Reset response pack context
            cw_pack_map_size(&s->pc_tx, 2);
            cw_pack_cstr(&s->pc_tx, "e"); cw_pack_signed(&s->pc_tx, ret);
            cw_pack_cstr(&s->pc_tx, "d"); cw_pack_cstr(&s->pc_tx, code2str(errors, ret));
            ESP_LOGE(LOG_TAG, "[%d] Frame error: (%d) %s", s->h, ret, code2str(errors, ret));
        }
    } else {
        s->conn_timeout = DEF_CONN_TIMEOUT; // Reload timeout on command success 
    }
    respond(s);
    return 0;
}

static int rx_cb(uint16_t conn, const uint8_t *data, size_t data_len) {
    int retval = 0;
    session_t *s = &session[conn];
    
    while(!xSemaphoreTake(session_sem, portMAX_DELAY));
    if(!s->connected) {
        retval = 1;
        goto exitfn;
    }
    if(s->blocked) {
        retval = 1;
        goto exitfn;
    }
    if (s->rx_buffer_len + data_len > RX_BUFFER_SIZE){
        retval = 1;
        ESP_LOGE(LOG_TAG, "[%d] RX buffer overflow", conn);
        goto exit_clear;
    }
    memcpy(&s->rx_buffer[s->rx_buffer_len], data, data_len);
    s->rx_buffer_len += data_len;

    cw_unpack_context upc;
    cw_unpack_context_init(&upc, s->rx_buffer, s->rx_buffer_len, NULL);
    cw_skip_items(&upc, 1);

    if(upc.return_code != CWP_RC_OK && upc.return_code != CWP_RC_END_OF_INPUT && upc.return_code != CWP_RC_BUFFER_UNDERFLOW) {
        ESP_LOGE(LOG_TAG, "[%d] MSGPACK decode error: %d", conn, upc.return_code);
    }

    if (upc.return_code == CWP_RC_OK) {
        cmd_cb(s);
        goto exit_clear;
    }
    goto exitfn;
exit_clear:
    s->rx_buffer_len = 0;
exitfn:    
    xSemaphoreGive(session_sem);
    return retval;
}

static esp_err_t init_flash() {
    esp_err_t err = nvs_flash_init();
    if(err == ESP_ERR_NVS_NO_FREE_PAGES) {
        // NVS partition was truncated and needs to be erased
        const esp_partition_t* nvs_partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, NULL);
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

static esp_err_t save_flash_config() {
    esp_err_t err = ESP_OK;

    config.cfg_version = FW_VER;
    err = nvs_set_blob(nvs_config_h, "config", &config, sizeof(config));
    if(err != ESP_OK) {
        goto exitfn;
    }
    err = nvs_commit(nvs_config_h);
    if(err != ESP_OK)
        goto exitfn;
    ESP_LOGI(LOG_TAG, "Config written to flash!");
    err = ESP_OK;
exitfn:
    if(err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "Error (%d) writing config to flash!", err);
    }
    return err;
}

static esp_err_t reset_flash_config(bool format) {
    size_t olen = 0;

    memset(&config, 0, sizeof(config)); 
    if (format) {
        ESP_LOGI(LOG_TAG, "Formating new config values...");
        strcpy(config.tz, "CET-1CEST,M3.5.0,M10.5.0/3");
        strcpy(config.tzn, "Europe/Madrid");
        crypto_box_keypair(config.public_key, config.secret_key);
        randombytes_buf(config.vk_id, sizeof(config.vk_id));
        mbedtls_base64_decode(config.ca_key, crypto_box_PUBLICKEYBYTES, &olen, (uint8_t*)CA_PK, strlen(CA_PK));
        if(crypto_box_beforenm(ca_shared, config.ca_key, config.secret_key) != 0) {
            ESP_LOGE(LOG_TAG, "Error computing ca shared key");
        }
    } else {
        ESP_LOGI(LOG_TAG, "Cleaning config values (factory reset)...");
    }
    return save_flash_config();
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
            ESP_LOGW(LOG_TAG, "Config not found, creating new one");
            err = reset_flash_config(false);
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
    ESP_LOGI(LOG_TAG, "Timezone:%s", config.tz);
    setenv("TZ", config.tz, 1);
    tzset();
    if(crypto_box_beforenm(ca_shared, config.ca_key, config.secret_key) != 0) {
        ESP_LOGE(LOG_TAG, "Error computing ca shared key");
    }
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

#ifdef I2C_SCL_GPIO
    // I2C setup
    i2c_config_t conf = {0};
    conf.mode = I2C_MODE_MASTER;
    conf.sda_io_num = I2C_SDA_GPIO;
    conf.sda_pullup_en = GPIO_PULLUP_ENABLE;
    conf.scl_io_num = I2C_SCL_GPIO;
    conf.scl_pullup_en = GPIO_PULLUP_ENABLE;
    conf.master.clk_speed = I2C_FREQ;
    esp_err_t ret = i2c_param_config(I2C_NUM_0, &conf);
    assert(ret == ESP_OK);
	ret = i2c_driver_install(I2C_NUM_0, conf.mode, 0, 0, 0);
    assert(ret == ESP_OK);
#endif
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
    printf("Magic:\"%s\"\n", magic);
    session_sem = xSemaphoreCreateMutex();
    xSemaphoreGive(session_sem);
    setup_gpio();
    ESP_ERROR_CHECK(init_flash());
    ESP_ERROR_CHECK(load_flash_config());
    config.boot_cnt ++;
    ESP_ERROR_CHECK(save_flash_config());
#ifdef RTC_DRIVER    
    if (hctosys() != 0) {
        ESP_LOGE(LOG_TAG, "Error reading hardware clock");
    }
#endif
    log_add(NULL, LOG_OP_BOOT, config.boot_cnt, 0);
    ESP_LOGI(LOG_TAG, "Boot counter: %u", config.boot_cnt);
    print_current_time(); 
    bin2b64(config.vk_id, sizeof(config.vk_id), chbuf, sizeof(chbuf));
    ESP_LOGI(LOG_TAG, "virkey ID: %s", chbuf);
    bin2b64(config.public_key, crypto_box_PUBLICKEYBYTES, chbuf, sizeof(chbuf));
    ESP_LOGI(LOG_TAG, "public key: %s", chbuf);
    bin2b64(config.ca_key, crypto_box_PUBLICKEYBYTES, chbuf, sizeof(chbuf));
    ESP_LOGI(LOG_TAG, "CA key: %s", chbuf);

    ESP_ERROR_CHECK(init_gatts(connect_cb, disconnect_cb, rx_cb, config.vk_id));

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
        } else if ((get_reset_button() == 0 && reset_button_tm == 0) || (!is_configured())) { // LED Blink
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
                    reset_flash_config(false);
                }
                for (int conn = 0; conn < CONFIG_BT_ACL_CONNECTIONS; conn ++){
                    if(session[conn].connected){
                        gatts_close_connection(conn, session[conn].gatts_if);
                    }
                }
                vTaskDelay(200 / portTICK_PERIOD_MS);
                reboot();
            }
        }
        // --- End Reset Timer

        xSemaphoreGive(session_sem);
    }
}