#!/usr/bin/env bash
#
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export CONTAINER_NAME=ci_native_previous_releases
export CI_IMAGE_NAME_TAG="docker.io/debian:bookworm"
# The official V3.0.1 Linux binary requires GLIBC_2.34, newer than Bullseye.
export PACKAGES="gcc-12 g++-12 python3-zmq"
export DEP_OPTS="NO_UPNP=1 NO_NATPMP=1 DEBUG=1 CC=gcc-12 CXX=g++-12"
export TEST_RUNNER_EXTRA="--previous-releases --coverage --extended --exclude feature_dbcrash"  # Run extended tests so that coverage does not fail, but exclude the very slow dbcrash
export RUN_UNIT_TESTS_SEQUENTIAL="true"
export RUN_UNIT_TESTS="false"
export GOAL="install"
export DOWNLOAD_PREVIOUS_RELEASES="true"
export BITCOIN_CONFIG="--enable-zmq --with-libs=no --with-gui=qt6 --enable-reduce-exports --enable-debug \
CFLAGS=\"-g0 -O2 -funsigned-char\" CPPFLAGS='-DBOOST_MULTI_INDEX_ENABLE_SAFE_MODE' CXXFLAGS=\"-g0 -O2 -funsigned-char\""
