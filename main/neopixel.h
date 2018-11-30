#pragma once
#include <driver/rmt.h>

esp_err_t neopixel_init();
esp_err_t neopixel_set(uint8_t r, uint8_t g, uint8_t b);
