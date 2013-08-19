#!/bin/sh
cd C_Extension
cmake -p CMakeLists.txt
make
cd ..
sudo ./ZeroAccessCrawlTwisted.py -l
