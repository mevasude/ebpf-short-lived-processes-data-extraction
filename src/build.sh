#!/bin/bash
sudo rm -rf *.o
export CXX=clang++
cmake . || exit $?
make || exit $?
