#include "boards.h"

#ifdef NEOPIXEL_GPIO

#include "neopixel.h"

#define DIVIDER 4 
#define DURATION 12.5 
#ifndef NEOPIXEL_T0H
#define NEOPIXEL_T0H   (  350 / (DURATION * DIVIDER))
#endif
#ifndef NEOPIXEL_T1H
#define NEOPIXEL_T1H   (  900 / (DURATION * DIVIDER))
#endif
#ifndef NEOPIXEL_T0L
#define NEOPIXEL_T0L   (  900 / (DURATION * DIVIDER))
#endif
#ifndef NEOPIXEL_T1L
#define NEOPIXEL_T1L   (  350 / (DURATION * DIVIDER))
#endif
#ifndef NEOPIXEL_TRS
#define NEOPIXEL_TRS   (50000 / (DURATION * DIVIDER))
#endif

#if !defined(NEOPIXEL_RGB) && !defined(NEOPIXEL_GRB)
#define NEOPIXEL_GRB
#endif

const rmt_item32_t bit0 = { .duration0 = NEOPIXEL_T0H, .level0 = 1, .duration1 = NEOPIXEL_T0L, .level1 = 0 }; // Logical 0
const rmt_item32_t bit1 = { .duration0 = NEOPIXEL_T1H, .level0 = 1, .duration1 = NEOPIXEL_T1L, .level1 = 0 }; // Logical 1
const rmt_item32_t rst = { .duration0 = NEOPIXEL_TRS, .level0 = 0, .duration1 = 0, .level1 = 0 }; // Reset

static rmt_item32_t pix_buf[25];

esp_err_t neopixel_init() {
    esp_err_t err;
    rmt_config_t config = {0};
    config.rmt_mode = RMT_MODE_TX;
    config.channel = RMT_CHANNEL_0;
    config.gpio_num = NEOPIXEL_GPIO;
    config.mem_block_num = 1;
    config.tx_config.loop_en = 0;
    config.tx_config.carrier_en = 0;
    config.tx_config.idle_output_en = 1;
    config.tx_config.idle_level = 0;
    config.clk_div = DIVIDER;

    err = rmt_config(&config);
    if (err != ESP_OK) {
        return err;
    }
    err = rmt_driver_install(config.channel, 0, 0);
    return err;
}

esp_err_t neopixel_set(uint8_t r, uint8_t g, uint8_t b) {
#ifdef NEOPIXEL_RGB    
    uint32_t rgb = ((uint32_t)r << 24) | ((uint32_t)g << 16) | ((uint32_t)b << 8);
#endif
#ifdef NEOPIXEL_GRB    
    uint32_t rgb = ((uint32_t)g << 24) | ((uint32_t)r << 16) | ((uint32_t)b << 8);
#endif
    rmt_wait_tx_done(RMT_CHANNEL_0, portMAX_DELAY);
    for (int i = 0; i < 24; i++ ) {
        if ((rgb & (1 << 31)) != 0) {
            pix_buf[i] = bit1;
        } else {
            pix_buf[i] = bit0;
        }
        rgb <<= 1;
    }
    pix_buf[24] = rst;
    return rmt_write_items(RMT_CHANNEL_0, pix_buf, 25, false);
}

#endif // NEOPIXEL_GPIO
