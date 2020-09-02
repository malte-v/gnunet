#!/bin/bash

# echo "Skipped"

pushd src/transport
make check TESTS='test_communicator_basic-tcp'
popd
