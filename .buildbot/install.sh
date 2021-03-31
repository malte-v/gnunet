#!/bin/bash

cd doc/tutorial; make tutorial.html &> /dev/null; cd -
cd doc/doxygen; make full &> /dev/null; cd -
make install
