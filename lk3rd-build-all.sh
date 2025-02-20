#!/bin/sh
set -e

./build.sh c1s
cp boot-c1s.img boot.img
tar -cvf boot-c1s.tar boot.img
./build.sh c2s
cp boot-c2s.img boot.img
tar -cvf boot-c2s.tar boot.img
./build.sh r8s
cp boot-r8s.img boot.img
tar -cvf boot-r8s.tar boot.img
./build.sh x1s
cp boot-x1s.img boot.img
tar -cvf boot-x1s.tar boot.img
./build.sh y2s
cp boot-y2s.img boot.img
tar -cvf boot-y2s.tar boot.img
./build.sh z3s
cp boot-z3s.img boot.img
tar -cvf boot-z3s.tar boot.img

rm boot.img

echo All done!
