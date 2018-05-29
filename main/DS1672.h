#pragma once
#include <stdint.h>
#include <stddef.h>
#include "esp_system.h"


#define DS1672_READ_ADDR               0xD1
#define DS1672_WRITE_ADDR              0xD0

#ifndef DS1672_EOSC 
    #define DS1672_EOSC                0b00000000
#endif

#ifndef DS1672_CHARGE_TRICKLE
    #define DS1672_CHARGE_TRICKLE      0b10101010
#endif

esp_err_t DS1672_Write(uint8_t addr, uint8_t *data, size_t count);
esp_err_t DS1672_Read(uint8_t addr, uint8_t *data, size_t count);

