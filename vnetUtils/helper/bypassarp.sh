#!/bin/bash

./vecho "\e[1;34m$0 $*\e[0m"
./vdo arptables -A INPUT -j DROP
./vdo arptables -A OUTPUT -j DROP