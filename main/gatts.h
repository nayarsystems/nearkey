#include "esp_bt_defs.h"

typedef int (*gatts_connect_cb_t)(const esp_bd_addr_t addr);
typedef int (*gatts_disconnect_cb_t)(const esp_bd_addr_t addr);
typedef int (*gatts_cmd_cb_t)(const char* cmd, size_t size);

int init_gatts(gatts_connect_cb_t conn_cb,
               gatts_disconnect_cb_t disconn_cb,
               gatts_cmd_cb_t cmd_cb,
               uint32_t key_counter,
               uint8_t* id);
esp_err_t gatts_close_connection();
ssize_t gatts_send_response(const char* resp);
