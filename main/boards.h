#pragma once 

#include "sdkconfig.h"

// Custom board
#ifdef CONFIG_VK_BOARD_CUSTOM
#include "custom_board.h"
#endif

// VK1X
#ifdef CONFIG_VK_BOARD_VK1X
#define HW_BOARD "VK1X"
#define ACTUATORS_GPIO { 18, 5 }
#define ACTUATORS_TOUT { 10, 10}
#define STATUS_LED_GPIO 32
#define RESET_BUTTON_GPIO 0
#define BUZZER_GPIO 12
#define I2C_SCL_GPIO 16
#define I2C_SDA_GPIO 13
#define I2C_FREQ 100000
#define RTC_DRIVER
#define RTC_DRIVER_DS1672
#endif


// Olimex EVB 
#ifdef CONFIG_VK_BOARD_OLIMEX_EVB
#define HW_BOARD "OLIMEX_EVB"
#define ACTUATORS_GPIO { 32, 33 }
#define ACTUATORS_TOUT { 10, 10}
#define STATUS_LED_GPIO -1
#define RESET_BUTTON_GPIO 34
#define I2C_SCL_GPIO 16
#define I2C_SDA_GPIO 13
#define I2C_FREQ 100000
#define RTC_DRIVER
#define RTC_DRIVER_PCF8563
#endif

// ESP32-T with ESP32-BIT
#ifdef CONFIG_VK_BOARD_ESP32T
#define HW_BOARD "ESP32_BIT"
#define ACTUATORS_GPIO { 32, 33 }
#define ACTUATORS_TOUT { 10, 10}
#define STATUS_LED_GPIO 2
#define RESET_BUTTON_GPIO 0
#define I2C_SCL_GPIO 12
#define I2C_SDA_GPIO 14
#define I2C_FREQ 100000
#define RTC_DRIVER
#define RTC_DRIVER_PCF8563
#endif
