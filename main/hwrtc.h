#pragma once

#include "boards.h"

int DS1672_hctosys(void);
int DS1672_systohc(void);
int PCF_hctosys(void);
int PCF_systohc(void);

#if defined(RTC_DRIVER_DS1672) || defined(RTC_DRIVER_PCF8563)
    #ifndef I2C_SCL_GPIO
        #error RTC clock needs I2C bus
    #endif
#endif

#if defined(RTC_DRIVER_DS1672)
    #define hctosys() DS1672_hctosys()
    #define systohc() DS1672_systohc()
#elif defined(RTC_DRIVER_PCF8563)
    #define hctosys() PCF_hctosys()
    #define systohc() PCF_systohc()
#else
    static int NOHW_hctosys() {return 0;}
    static int NOHW_systohc() {return 0;}
    #define hctosys() NOHW_hctosys()
    #define systohc() NOHW_systohc()
#endif

