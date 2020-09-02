#!/bin/bash

# echo "Skipped"

pushd src/transport
make check TESTS='test_communicator_basic-tcp'
cat src/transport/test-suite.log
popd
