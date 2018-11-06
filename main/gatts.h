#pragma once

#include "esp_bt_defs.h"

#define GATTS_EVT_ADV_START_OK  1
#define GATTS_EVT_ADV_START_ERR 2
#define GATTS_EVT_ADV_STOP_OK   3
#define GATTS_EVT_ADV_STOP_ERR  4

typedef int (*gatts_connect_cb_t)(uint16_t conn, uint16_t gatts_if, const esp_bd_addr_t addr);
typedef int (*gatts_disconnect_cb_t)(uint16_t conn);
typedef int (*gatts_rx_cb_t)(uint16_t conn, const uint8_t* cmd, size_t size);
typedef int (*gatts_evt_cb_t)(int evt);

typedef struct gatts_config_s {
    gatts_connect_cb_t conn_cb;
    gatts_disconnect_cb_t disconn_cb;
    gatts_rx_cb_t rx_cb;
    gatts_evt_cb_t evt_cb;
    uint8_t manufacturer_id[2];
    uint8_t device_id[6];
    uint8_t service_uuid128[16];
    uint8_t characteristic_uuid_128[16];
    bool use_srv_data;
    char name[17];
    int adv_dbm;
} gatts_config_t;


int init_gatts(const gatts_config_t *cfg);

esp_err_t gatts_close_connection(uint16_t conn_id, uint16_t gatts_if);
ssize_t gatts_send_response(uint16_t conn_id, uint16_t gatts_if, const uint8_t *resp, size_t len);
esp_err_t gatts_start_adv();
esp_err_t gatts_stop_adv();
