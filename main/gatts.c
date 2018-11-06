// Copyright 2015-2016 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_bt.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "gatts.h"

#include "sdkconfig.h"

#define LOG_TAG "GATTS"

// Declare static functions
static void
gatts_profile_a_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t* param);
// ---

#define GATTS_NUM_HANDLE_TEST_A 4

#define TEST_DEVICE_NAME "pay2machine.com"

static uint8_t raw_adv_data[31] = {
    0x02, // Flags field size
    0x01, // Flags
    0x06, // General Discoverable Mode & BR/EDR Not Supported
    0x11, // 128 bit services field size
    0x07, // 128 bit services complete list
    0x68, 0x8c, 0x49, 0x0d, 0x54, 0x56, 0xfc, 0x83, 0x5c, 0x47, 0xb3, 0x80, 0x73, 0xc2, 0xda, 0x00,// Service
    0x09, 0xff, 0xce, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00                                     // pay2machine ID
};
#define ADV_SERVICE_UUID_OFFSET 5
#define ADV_MANUFACTURER_OFFSET 23
#define ADV_DEVID_OFFSET 25

static uint8_t raw_scan_rsp_data[31] = {
    0x02, // Flags field size
    0x01, // Flags
    0x06, // General Discoverable Mode & BR/EDR Not Supported
    0x02, // Tx power field size
    0x0a, // Tx power
    0xeb, // Tx Power Value (offset 5)
    0x10, // Name field Size (name size + 1, offset 6)
    0x09, // Name
    'p', 'a', 'y', '2', 'm', 'a', 'c', 'h', 'i', 'n', 'e', '.', 'c', 'o', 'm', // (name, offset 8)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // Padding up to 31 bytes
};
#define ADV_RESP_TX_POWER_OFFSET 5
#define ADV_RESP_NAME_SIZE_OFFSET 6
#define ADV_RESP_NAME_OFFSET 8


static esp_ble_adv_params_t test_adv_params = {
    .adv_int_min = 0x20,
    .adv_int_max = 0x40,
    .adv_type = ADV_TYPE_IND,
    .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
    //.peer_addr            =
    //.peer_addr_type       =
    .channel_map = ADV_CHNL_ALL,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

// GATTS config
static gatts_config_t gatts_config = {0};
// ---


#define PROFILE_NUM 1
#define PROFILE_A_APP_ID 0

static uint16_t notif_stats[CONFIG_BT_ACL_CONNECTIONS];

struct gatts_profile_inst {
    esp_gatts_cb_t gatts_cb;
    //bool connected;
    uint16_t gatts_if;
    uint16_t app_id;
    uint16_t service_handle;
    esp_gatt_srvc_id_t service_id;
    uint16_t char_handle;
    esp_bt_uuid_t char_uuid;
    esp_gatt_perm_t perm;
    uint16_t descr_handle;
    esp_bt_uuid_t descr_uuid;
};

/* One gatt-based profile one app_id and one gatts_if, this array will store the gatts_if returned by ESP_GATTS_REG_EVT
 */
static struct gatts_profile_inst gl_profile_tab[PROFILE_NUM] = {
        [PROFILE_A_APP_ID] =
            {
                .gatts_cb = gatts_profile_a_event_handler,
                .gatts_if = ESP_GATT_IF_NONE, /* Not get the gatt_if, so initial is ESP_GATT_IF_NONE */
            },
};

static void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t* param) {
    int evt = 0;

    switch(event) {
    case ESP_GAP_BLE_ADV_DATA_SET_COMPLETE_EVT:
        break;
    case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
        break;
    case ESP_GAP_BLE_SCAN_RSP_DATA_RAW_SET_COMPLETE_EVT:
        break;
    case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
        if(param->adv_start_cmpl.status != ESP_BT_STATUS_SUCCESS) {
            evt = GATTS_EVT_ADV_START_ERR;
        } else {
            evt = GATTS_EVT_ADV_START_OK;
        }
        break;
    case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
        if(param->adv_stop_cmpl.status != ESP_BT_STATUS_SUCCESS) {
            evt = GATTS_EVT_ADV_STOP_ERR;
        } else {
            evt = GATTS_EVT_ADV_STOP_OK;
        }
        break;
    default:
        break;
    }
    if (evt > 0 && gatts_config.evt_cb != NULL) {
        gatts_config.evt_cb(evt);
    }
}

static void
gatts_profile_a_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t* param) {
    static esp_gatt_rsp_t rsp;

    switch(event) {
    case ESP_GATTS_REG_EVT: {
        ESP_LOGI(LOG_TAG, "REGISTER_APP_EVT, status %d, app_id %d", param->reg.status, param->reg.app_id);
        gl_profile_tab[PROFILE_A_APP_ID].service_id.is_primary = true;
        gl_profile_tab[PROFILE_A_APP_ID].service_id.id.inst_id = 0x00;
        gl_profile_tab[PROFILE_A_APP_ID].service_id.id.uuid.len = ESP_UUID_LEN_128;
        memcpy(gl_profile_tab[PROFILE_A_APP_ID].service_id.id.uuid.uuid.uuid128, &raw_adv_data[ADV_SERVICE_UUID_OFFSET], ESP_UUID_LEN_128);

        esp_ble_gap_set_device_name(TEST_DEVICE_NAME);
        esp_ble_gap_config_adv_data_raw(raw_adv_data, sizeof(raw_adv_data));
        esp_ble_gap_config_scan_rsp_data_raw(raw_scan_rsp_data, ADV_RESP_NAME_OFFSET + raw_scan_rsp_data[ADV_RESP_NAME_SIZE_OFFSET] - 1);
        esp_ble_gatts_create_service(gatts_if, &gl_profile_tab[PROFILE_A_APP_ID].service_id, GATTS_NUM_HANDLE_TEST_A);
        break;
    }
    case ESP_GATTS_READ_EVT: {
        ESP_LOGI(LOG_TAG, "[%d] GATT_READ_EVT, trans_id %d, handle %d", param->read.conn_id,
                 param->read.trans_id, param->read.handle);
        memset(&rsp, 0, sizeof(esp_gatt_rsp_t));
        rsp.attr_value.handle = param->read.handle;
        if(param->read.handle == gl_profile_tab[PROFILE_A_APP_ID].descr_handle) {
            ESP_LOGD(LOG_TAG, "descriptor read");
            rsp.attr_value.len = 2;
            memcpy(&rsp.attr_value.value[0], &notif_stats[param->read.conn_id], 2);
            esp_ble_gatts_send_response(gatts_if, param->read.conn_id, param->read.trans_id, ESP_GATT_OK, &rsp);
            break;
        }
        if(param->read.handle == gl_profile_tab[PROFILE_A_APP_ID].char_handle) {
            ESP_LOGD(LOG_TAG, "char handle read");
        } else if(param->read.handle == gl_profile_tab[PROFILE_A_APP_ID].service_handle) {
            ESP_LOGD(LOG_TAG, "service handle read");
        } else {
            ESP_LOGW(LOG_TAG, "unknown read");
        }
        rsp.attr_value.len = 1;
        rsp.attr_value.value[0] = 0;
        esp_ble_gatts_send_response(gatts_if, param->read.conn_id, param->read.trans_id, ESP_GATT_OK, &rsp); //Default response
        break;
    }
    case ESP_GATTS_WRITE_EVT: {
        ESP_LOGD(LOG_TAG, "[%d] GATT_WRITE_EVT, trans_id %d, handle %d, len %d, resp %d", param->write.conn_id,
                 param->write.trans_id, param->write.handle, param->write.len, param->write.need_rsp);
        int res = 0;

        if(param->write.handle == gl_profile_tab[PROFILE_A_APP_ID].descr_handle) {
            notif_stats[param->write.conn_id] = *((uint16_t*)param->write.value);
            if(param->write.need_rsp) {
                esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, NULL);
            }
            break;
        }

        memset(&rsp, 0, sizeof(esp_gatt_rsp_t));
        rsp.attr_value.handle = param->write.handle;
        memcpy(rsp.attr_value.value, param->write.value, param->write.len);
        rsp.attr_value.len = param->write.len;
        rsp.attr_value.offset = param->write.len;

        if (gatts_config.rx_cb != NULL) {
            res = gatts_config.rx_cb(param->write.conn_id, param->write.value, param->write.len);    
        }
        if(param->write.need_rsp) {
            if(param->write.is_prep) {
                esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, &rsp);
            } else {
                esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, NULL);
            }
        }
        if(res != 0) {
            esp_ble_gatts_close(gatts_if, param->connect.conn_id);
        }
        break;
    }
    case ESP_GATTS_EXEC_WRITE_EVT:
        ESP_LOGD(LOG_TAG, "[%d] GATT_EXEC_WRITE_EVT, trans_id %d", param->exec_write.conn_id,
                 param->exec_write.trans_id);
        esp_ble_gatts_send_response(gatts_if, param->exec_write.conn_id, param->exec_write.trans_id, ESP_GATT_OK, NULL);
        break;
    case ESP_GATTS_MTU_EVT:
    case ESP_GATTS_CONF_EVT:
    case ESP_GATTS_UNREG_EVT:
        break;
    case ESP_GATTS_CREATE_EVT: {
        ESP_LOGI(LOG_TAG, "CREATE_SERVICE_EVT, status %d,  service_handle %d", param->create.status,
                 param->create.service_handle);
        gl_profile_tab[PROFILE_A_APP_ID].service_handle = param->create.service_handle;
        gl_profile_tab[PROFILE_A_APP_ID].char_uuid.len = ESP_UUID_LEN_128;
        memcpy(gl_profile_tab[PROFILE_A_APP_ID].char_uuid.uuid.uuid128, gatts_config.characteristic_uuid_128, ESP_UUID_LEN_128);

        esp_ble_gatts_start_service(gl_profile_tab[PROFILE_A_APP_ID].service_handle);

        esp_ble_gatts_add_char(
            gl_profile_tab[PROFILE_A_APP_ID].service_handle, &gl_profile_tab[PROFILE_A_APP_ID].char_uuid,
            ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
            ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_WRITE_NR | ESP_GATT_CHAR_PROP_BIT_WRITE | ESP_GATT_CHAR_PROP_BIT_NOTIFY, NULL, NULL);
        break;
    }
    case ESP_GATTS_ADD_INCL_SRVC_EVT:
        break;
    case ESP_GATTS_ADD_CHAR_EVT:
        ESP_LOGI(LOG_TAG, "ADD_CHAR_EVT, status %d,  attr_handle %d, service_handle %d\n", param->add_char.status,
                 param->add_char.attr_handle, param->add_char.service_handle);
        gl_profile_tab[PROFILE_A_APP_ID].char_handle = param->add_char.attr_handle;
        gl_profile_tab[PROFILE_A_APP_ID].descr_uuid.len = ESP_UUID_LEN_16;
        gl_profile_tab[PROFILE_A_APP_ID].descr_uuid.uuid.uuid16 = ESP_GATT_UUID_CHAR_CLIENT_CONFIG;
        esp_ble_gatts_add_char_descr(gl_profile_tab[PROFILE_A_APP_ID].service_handle,
                                     &gl_profile_tab[PROFILE_A_APP_ID].descr_uuid,
                                     ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE, NULL, NULL);

        break;

    case ESP_GATTS_ADD_CHAR_DESCR_EVT:
        ESP_LOGI(LOG_TAG, "ADD_DESCR_EVT, status %d, attr_handle %d, service_handle %d", param->add_char_descr.status,
                 param->add_char_descr.attr_handle, param->add_char_descr.service_handle);
        gl_profile_tab[PROFILE_A_APP_ID].descr_handle = param->add_char_descr.attr_handle;
        break;
    case ESP_GATTS_DELETE_EVT:
        break;
    case ESP_GATTS_START_EVT:
        ESP_LOGI(LOG_TAG, "SERVICE_START_EVT, status %d, service_handle %d", param->start.status,
                 param->start.service_handle);
        break;
    case ESP_GATTS_STOP_EVT:
        break;
    case ESP_GATTS_CONNECT_EVT: {
        ESP_LOGI(LOG_TAG, "CONNECT_EVT, ConnID %d", param->connect.conn_id);
        if(gatts_config.conn_cb != NULL) {
            if(gatts_config.conn_cb(param->connect.conn_id, gatts_if, param->connect.remote_bda)) {
                esp_ble_gatts_close(gatts_if, param->connect.conn_id);
                break;
            }
        }
        break;
    }
    case ESP_GATTS_DISCONNECT_EVT:
        if(gatts_config.disconn_cb != NULL) {
            gatts_config.disconn_cb(param->disconnect.conn_id);
            notif_stats[param->disconnect.conn_id] = 0;
        }
        break;
    case ESP_GATTS_OPEN_EVT:
    case ESP_GATTS_CANCEL_OPEN_EVT:
    case ESP_GATTS_CLOSE_EVT:
    case ESP_GATTS_LISTEN_EVT:
    case ESP_GATTS_CONGEST_EVT:
    default:
        break;
    }
}

static void gatts_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t* param) {
    /* If event is register event, store the gatts_if for each profile */
    if(event == ESP_GATTS_REG_EVT) {
        if(param->reg.status == ESP_GATT_OK) {
            gl_profile_tab[param->reg.app_id].gatts_if = gatts_if;
        } else {
            ESP_LOGI(LOG_TAG, "Reg app failed, app_id %04x, status %d", param->reg.app_id, param->reg.status);
            return;
        }
    }

    /* If the gatts_if equal to profile A, call profile A cb handler,
     * so here call each profile's callback */
    do {
        int idx;
        for(idx = 0; idx < PROFILE_NUM; idx++) {
            if(gatts_if == ESP_GATT_IF_NONE || /* ESP_GATT_IF_NONE, not specify a certain gatt_if, need to call every
                                                  profile cb function */
               gatts_if == gl_profile_tab[idx].gatts_if) {
                if(gl_profile_tab[idx].gatts_cb) {
                    gl_profile_tab[idx].gatts_cb(event, gatts_if, param);
                }
            }
        }
    } while(0);
}

static int dbm2esp(int dbm) {
#ifdef ESP_PWR_LVL_P9 // New power macros IDF > 3.1
    if (dbm <= -12) return ESP_PWR_LVL_N12;
    if (dbm <= -9)  return ESP_PWR_LVL_N9;
    if (dbm <= -6)  return ESP_PWR_LVL_N6;
    if (dbm <= -3)  return ESP_PWR_LVL_N3;
    if (dbm <= 0)   return ESP_PWR_LVL_N0;
    if (dbm <= 3)   return ESP_PWR_LVL_P3;
    if (dbm <= 6)   return ESP_PWR_LVL_P6;
                    return ESP_PWR_LVL_P9;
#else
    if (dbm <= -12) return ESP_PWR_LVL_N14;
    if (dbm <= -9)  return ESP_PWR_LVL_N11;
    if (dbm <= -6)  return ESP_PWR_LVL_N8;
    if (dbm <= -3)  return ESP_PWR_LVL_N5;
    if (dbm <= 0)   return ESP_PWR_LVL_N2;
    if (dbm <= 3)   return ESP_PWR_LVL_P1;
    if (dbm <= 6)   return ESP_PWR_LVL_P4;
                    return ESP_PWR_LVL_P7;
#endif                     
}


int init_gatts(const gatts_config_t *cfg) {
    esp_err_t ret = 0;

    memcpy(&gatts_config, cfg, sizeof(gatts_config_t));
    if (gatts_config.use_srv_data) {
        raw_adv_data[ADV_MANUFACTURER_OFFSET - 1] = 0x16;
    } else {
        raw_adv_data[ADV_MANUFACTURER_OFFSET - 1] = 0xff;
    }
    memcpy(&raw_adv_data[ADV_MANUFACTURER_OFFSET], gatts_config.manufacturer_id, sizeof(gatts_config.manufacturer_id));
    memcpy(&raw_adv_data[ADV_DEVID_OFFSET], gatts_config.device_id, sizeof(gatts_config.device_id));
    memcpy(&raw_adv_data[ADV_SERVICE_UUID_OFFSET], gatts_config.service_uuid128, sizeof(gatts_config.service_uuid128));
    size_t name_len = strlen(gatts_config.name);
    if (name_len > 16) {
        name_len = 16;
    }
    raw_scan_rsp_data[ADV_RESP_NAME_SIZE_OFFSET] = name_len + 1;
    memcpy(&raw_scan_rsp_data[ADV_RESP_NAME_OFFSET], gatts_config.name, name_len);

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ret = esp_bt_controller_init(&bt_cfg);
    if(ret) {
        ESP_LOGE(LOG_TAG, "%s initialize controller failed", __func__);
        return ESP_FAIL;
    }

    ret = esp_bt_controller_enable(ESP_BT_MODE_BLE);
    if(ret) {
        ESP_LOGE(LOG_TAG, "%s enable controller failed", __func__);
        return ESP_FAIL;
    }
    ret = esp_bluedroid_init();
    if(ret) {
        ESP_LOGE(LOG_TAG, "%s init bluetooth failed", __func__);
        return ESP_FAIL;
    }
    ret = esp_bluedroid_enable();
    if(ret) {
        ESP_LOGE(LOG_TAG, "%s enable bluetooth failed", __func__);
        return ESP_FAIL;
    }
    ret = esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, dbm2esp(gatts_config.adv_dbm));
    if(ret) {
        ESP_LOGE(LOG_TAG, "%s ble tx power set failed", __func__);
    }
    ret = esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, dbm2esp(99)); // Max power
    if(ret) {
        ESP_LOGE(LOG_TAG, "%s ble tx power set failed", __func__);
    }

    esp_ble_gatts_register_callback(gatts_event_handler);
    esp_ble_gap_register_callback(gap_event_handler);
    esp_ble_gatts_app_register(PROFILE_A_APP_ID);
    return ESP_OK;
}

esp_err_t gatts_close_connection(uint16_t conn_id, uint16_t gatts_if) {
        return esp_ble_gatts_close(gatts_if, conn_id);
}

esp_err_t gatts_start_adv() {
    return esp_ble_gap_start_advertising(&test_adv_params);
}

esp_err_t gatts_stop_adv() {
    return esp_ble_gap_stop_advertising();
}

ssize_t gatts_send_response(uint16_t conn_id, uint16_t gatts_if, const uint8_t* resp, size_t len) {
    esp_err_t res = ESP_OK;
    ssize_t sent = 0;
    uint8_t* ptr = (uint8_t *)resp;

    while(len) {
        int chunk_len = len;
        if(chunk_len > 20) {
            chunk_len = 20;
        }
        res = esp_ble_gatts_send_indicate(
            gatts_if, conn_id,
            gl_profile_tab[PROFILE_A_APP_ID].char_handle, chunk_len, ptr, false);
        if(res != ESP_OK) {
            ESP_LOGE(LOG_TAG, "Error sending notification");
        } else {
            ESP_LOGD(LOG_TAG, "Notification sent");
        }
        len -= chunk_len;
        ptr += chunk_len;
        sent += chunk_len;
    }
    return sent;
}
