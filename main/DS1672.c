#include "boards.h"

#ifdef RTC_DRIVER_DS1672

#include "esp_system.h"
#include "DS1672.h"
#include "driver/i2c.h"
#include "hwrtc.h"

#include <stdlib.h>
#include <time.h>
#include <sys/time.h>



int DS1672_Write(uint8_t addr, uint8_t *data, size_t count) {
	i2c_cmd_handle_t cmd = i2c_cmd_link_create();
	i2c_master_start(cmd);
	i2c_master_write_byte(cmd, DS1672_WRITE_ADDR, true);
	i2c_master_write_byte(cmd, addr, true);
	i2c_master_write(cmd, data, count, true);
	i2c_master_stop(cmd);
	esp_err_t ret = i2c_master_cmd_begin(I2C_NUM_0, cmd, 1000 / portTICK_PERIOD_MS);
    i2c_cmd_link_delete(cmd);
    return ret;
}

int DS1672_Read(uint8_t addr, uint8_t *data, size_t count) {
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
	i2c_master_start(cmd);
	i2c_master_write_byte(cmd, DS1672_WRITE_ADDR, true);
	i2c_master_write_byte(cmd, addr, true);
	//i2c_master_stop(cmd);
	i2c_master_start(cmd);
	i2c_master_write_byte(cmd, DS1672_READ_ADDR, true);
	i2c_master_read(cmd, data, count, I2C_MASTER_LAST_NACK);
	i2c_master_stop(cmd);
	esp_err_t ret = i2c_master_cmd_begin(I2C_NUM_0, cmd, 1000 / portTICK_PERIOD_MS);
    i2c_cmd_link_delete(cmd);
    return ret;
}


int DS1672_set_timestamp(int64_t ts) {
    uint8_t buf[6];
    buf[0] = (ts & 0x000000ff);
    buf[1] = (ts & 0x0000ff00) >> 8;
    buf[2] = (ts & 0x00ff0000) >> 16;
    buf[3] = (ts & 0xff000000) >> 24;
    buf[4] = DS1672_EOSC;
    buf[5] = DS1672_CHARGE_TRICKLE;
    return DS1672_Write(0, buf, sizeof(buf));
}

int DS1672_get_timestamp(int64_t *ts) {
    uint8_t buf[6];
    
    esp_err_t err = DS1672_Read(0, buf, sizeof(buf));

    if (err != ESP_OK) {
        return err;
    }

    *ts = (int64_t) buf[0];
    *ts += ((int64_t) buf[1]) << 8;
    *ts += ((int64_t) buf[2]) << 16;
    *ts += ((int64_t) buf[3]) << 24;

    if (buf[4] != DS1672_EOSC || buf[5] != DS1672_CHARGE_TRICKLE){
        err = -1;
    }
    return err;
}


int hctosys() {
    int64_t ts = 0;
    struct timeval tv = {0};

    int ret = DS1672_get_timestamp(&ts);
    if (ret != 0) {
        return ret;
    }

	tv.tv_sec = ts;
	tv.tv_usec = 0;
	return  settimeofday(&tv, NULL);
}

int systohc() {
    time_t now = time(NULL);
    return DS1672_set_timestamp(now);
}

#endif //RTC_DRIVER_DS1672