#include "esp_bt_defs.h"

typedef int (*gatts_connect_cb_t)(uint16_t conn, uint16_t gatts_if, const esp_bd_addr_t addr);
typedef int (*gatts_disconnect_cb_t)(uint16_t conn);
typedef int (*gatts_cmd_cb_t)(uint16_t conn, const char* cmd, size_t size);

int init_gatts(gatts_connect_cb_t conn_cb,
               gatts_disconnect_cb_t disconn_cb,
               gatts_cmd_cb_t cmd_cb,
               uint32_t key_counter);

esp_err_t gatts_close_connection(uint16_t conn_id, uint16_t gatts_if);
ssize_t gatts_send_response(uint16_t conn_id, uint16_t gatts_if, const char* resp);
esp_err_t gatts_start_adv();
esp_err_t gatts_stop_adv();
