# Virkey
Virkey aims to be a professional access control device using Bluetooth Low Energy (BLE).

## Use cases
* Garage door opener.
* Safe switch.
* Clocking machine.

## Main characteristics
- Asymmetric encryption algorithm ([libsodium](https://download.libsodium.org/doc/))
- Unlimited users per device.
- Over-the-Air (OTA) firmware updates. The updates are transparent through users normal utilization. For example, when users open a garage door they send firmware chunks transparently. When all chunks are received, Virkey hardware switches to new firmware version.
This feature is crucial to fix potential security or functionality flaws.
- Supports complex time restriction rules.
- Android and iOS app (they are free but not open-source right now).
  * [Android](https://play.google.com/store/apps/details?id=com.virkey.basic.cordova)
  * [iOS](https://itunes.apple.com/us/app/virkey-cloud/id1315035954?mt=8)


## Supported ESP32 boards
- [OLIMEX ESP32 EVB](https://www.olimex.com/Products/IoT/ESP32-EVB/open-source-hardware)
- [DIYMALL RELAY32](http://www.diymalls.com/esp32-wifi-bluetooth-relay-module)
- [ARMTRONIX QUAD RELAY](https://www.tindie.com/products/Armtronix/wifibt-esp32-quad-relay-board-amazon-alexa/)
- [TTGO MINI 32 (with relay shield)](https://es.aliexpress.com/store/product/20-EN-1-KITS-TTGO-MINI32-V2-0-ESP32-WiFi-Bluetooth-learning-kit-MINI-D1-IOT/2787042_32845377733.html)
- [TTGO T8](https://es.aliexpress.com/store/product/T8-V1-3-TTGO-ESP32-4-MB-PSRAM-TF-3D-antena-WiFi-m-dulo-Bluetooth-ESP32/1983387_32853967655.html)
- GENERIC A. Generic board using these GPIOs:
  * GPIO 0  <- Factory reset / Boot loader.
  * GPIO 2  -> Status LED.
  * GPIO 32 -> Actuator 0 (Relay 1)
  * GPIO 33 -> Actuator 1 (Relay 2)
  
  See full details in [boards.h](https://github.com/nayarsystems/virkey/blob/master/main/boards.h) and [kconfig](https://github.com/nayarsystems/virkey/blob/master/main/Kconfig)

## Flash your board with precompiled images
First you must install [esptool](https://github.com/espressif/esptool).

Go to `bin` directory located in Virkey working directory.
Run this command replacing COM_PORT with the correct com port and BOARD_XXX.bin with the correct board file.
```
esptool.py --chip esp32 --port COM_PORT --baud 115200 --before default_reset --after hard_reset write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect 0x1000 bootloader.bin 0x10000 BOARD_XXX.bin 0x8000 partitions.bin
```

If you want erase full flash before flashing Virkey (YOU WILL LOSE PREVIOUS CONFIGURATIONS), run this command:
```
esptool.py --chip esp32 --port COM_PORT --baud 115200 erase_flash
```
## Compile sources
Follow [esp-idf](https://github.com/espressif/esp-idf) install instructions.

Virkey uses version 3.0 of esp-idf. So you must checkout this branch on esp-idf working directory.
 ```
 git checkout release/v3.0
 git submodule update
 ```
 If you want reproduce the same official binary, you must checkout esp-idf to commit referred in [idfver](https://github.com/nayarsystems/virkey/blob/master/idfver) file.

 "master" branch points to last stable release. Development unstable code lives in "develop" branch.

Once esp-idf is installed, you must select the right board.
On Virkey's working directory:
```
$ make menuconfig
--> Component config
    --> Virkey.com config
        --> Board
```
Compile and flash:

```
$ make -j4
$ make erase_flash
$ make flash
```
Execute `make monitor` after successful flash if you want see Virkey's debug output.

## Using Virkey
After successful flash, launch Virkey APP and follow instructions to add your device to your account.
You can also manage your account with the web manager [here](https://admin.virkey.com)



