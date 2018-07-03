#!/bin/bash

boards=`grep CONFIG_VK_BOARD* sdkconfig | sed 's/CONFIG_VK_BOARD_\(.*\)=.*$/\1/'`

for board in $boards; do
    echo Compiling \($board\) board
    #Reset boards flags
    sed -i 's/CONFIG_VK_BOARD_\(.*\)=y$/CONFIG_VK_BOARD_\1=/' sdkconfig
    #Set current board flag
    sed -i "s/CONFIG_VK_BOARD_$board=.*/CONFIG_VK_BOARD_$board=y/" sdkconfig
    make -j4
    cp build/Virkey.bin bin/BOARD_$board.bin
done