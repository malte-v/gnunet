#!/bin/bash

# echo "Skipped"

pushd src/transport
make check TESTS='test_communicator_basic-tcp test_communicator_rekey-tcp'
pkill --signal 9 -U buildbot gnunet
popd
