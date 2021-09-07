#!/bin/bash
echo "Cleanup old installation..."
rm -rf /tmp/gnunet
./bootstrap && ./configure --prefix=/tmp/gnunet --enable-experimental && make -j16
