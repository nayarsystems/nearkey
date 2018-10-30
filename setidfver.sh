#! /bin/bash
IDFVER=`cat idfver`
cd $IDF_PATH
git fetch --all
git clean -d -ff
git checkout $IDFVER
git clean -d -ff
git submodule update


