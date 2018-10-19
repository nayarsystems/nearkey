#! /bin/bash
IDFVER=`cat idfver`
cd $IDF_PATH
git co $IDFVER
git pull
git submodule update

