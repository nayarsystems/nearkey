#pragma once

#include "esp_bt_defs.h"

typedef int (*gatts_connect_cb_t)(uint16_t conn, uint16_t gatts_if, const esp_bd_addr_t addr);
typedef int (*gatts_disconnect_cb_t)(uint16_t conn);
typedef int (*gatts_rx_cb_t)(uint16_t conn, const uint8_t* cmd, size_t size);

int init_gatts(gatts_connect_cb_t conn_cb,
               gatts_disconnect_cb_t disconn_cb,
               gatts_rx_cb_t rx_cb,
               const uint8_t *vk_id);

esp_err_t gatts_close_connection(uint16_t conn_id, uint16_t gatts_if);
ssize_t gatts_send_response(uint16_t conn_id, uint16_t gatts_if, const uint8_t *resp, size_t len);
esp_err_t gatts_start_adv();
esp_err_t gatts_stop_adv();
