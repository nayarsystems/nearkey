# Virkey
High security multi-purpose Bluetooth Low Energy (BLE) relays.

## Main characteristics
- Asymmetric encryption algorithm ([libsodium](https://download.libsodium.org/doc/))
- Unlimited users per device.
- Over-the-Air (OTA) firmware updates. The updates are transparent through users normal utilization. For example, when users open a garage door they send firmware chunks transparently. When all chunks are received, virkey hardware switches to new firmware version.
This feature is crucial to fix potential security or functionality flaws.
- Supports complex time restriction rules.
- Android and iOS app (they are free but not open-source right now).
  * [Android](https://play.google.com/store/apps/details?id=com.virkey.basic.cordova)
  * [iOS](https://itunes.apple.com/us/app/virkey-cloud/id1315035954?mt=8)


## Supported ESP32 boards
- [OLIMEX ESP32 EVB](https://www.olimex.com/Products/IoT/ESP32-EVB/open-source-hardware)
- [DIYMALL RELAY32](http://www.diymalls.com/esp32-wifi-bluetooth-relay-module)
- [TTGO MINI 32](http://ttgobbs.com/viewthread.php?tid=14448&extra=&ordertype=1)
- [TTGO T8](http://www.ttgobbs.com/redirect.php?tid=11915&goto=lastpost)
- GENERIC A. Generic board using these GPIOs:
  * GPIO 0  <- Factory reset / Boot loader.
  * GPIO 2  -> Status LED.
  * GPIO 32 -> Actuator 0 (Relay 1)
  * GPIO 33 -> Actuator 1 (Relay 2)
  
  See full details in [boards.h](https://github.com/nayarsystems/virkey/blob/master/main/boards.h) and [kconfig](https://github.com/nayarsystems/virkey/blob/master/main/Kconfig)

## Compile
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

## Using virkey
After successful flash, launch Virkey APP and follow instructions.


