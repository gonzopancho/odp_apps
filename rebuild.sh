#!/bin/bash

white='\033[1;37m'
NC='\033[0m' # No Color

git pull

if [ -d libpcap/libpcap/ ]; then
	rm -rf libpcap/libpcap/
	echo -e "${white}libpcap removed and will be rebuilt${NC}"
else
	echo -e "${white}libpcap were not found. will be downloaded and built${NC}"
fi

make
