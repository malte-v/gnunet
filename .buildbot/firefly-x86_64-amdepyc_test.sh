#!/bin/bash

# echo "Skipped"

pushd src/transport
make check TESTS='test_communicator_basic-tcp'
cat test-suite.log
pkill --signal 9 -U buildbot gnunet
make check TESTS='test_communicator_rekey-tcp'
pkill --signal 9 -U buildbot gnunet
popd
