#!/bin/bash -x

# Make sure we exit if there is a failure
set -e

STP_LOG="$(pwd)/stp-build.log"

if [ "x${STP_VERSION}" != "x" ]; then
    # Get Sanitizer flags
    source ${KLEE_SRC}/.travis/sanitizer_flags.sh

    # Build minisat
    git clone https://github.com/stp/minisat
    cd minisat
    mkdir build
    cd build
    MINISAT_DIR=`pwd`
    CFLAGS="${SANITIZER_C_FLAGS}" \
    CXXFLAGS="${SANITIZER_CXX_FLAGS}" \
    cmake -DCMAKE_INSTALL_PREFIX=/usr ..
    make
    sudo make install
    cd ../../

    # Build cryptominisat4
    wget -O cryptominisat-4.5.3.zip https://github.com/msoos/cryptominisat/archive/refs/tags/4.5.3.zip
    unzip cryptominisat-4.5.3.zip
    cd cryptominisat-4.5.3 && mkdir build && cd build && \
    CFLAGS="${SANITIZER_C_FLAGS}" \
    CXXFLAGS="${SANITIZER_CXX_FLAGS}" \
    cmake -DSTATICCOMPILE=OFF -DCMAKE_INSTALL_PREFIX=/usr .. && \
    make && \
    sudo make install && sudo ldconfig && \
    cd ../..

    # Build STP
    git clone --depth 1 -b "${STP_VERSION}" https://github.com/stp/stp src
    mkdir build
    cd build
    # Disabling building of shared libs is a workaround.
    # Don't build against boost because that is broken when mixing packaged boost libraries and gcc 4.8
    CFLAGS="${SANITIZER_C_FLAGS}" \
    CXXFLAGS="${SANITIZER_CXX_FLAGS}" \
    cmake -DBUILD_SHARED_LIBS:BOOL=ON -DENABLE_PYTHON_INTERFACE:BOOL=OFF -DNO_BOOST:BOOL=ON ../src

    set +e # Do not exit if build fails because we need to display the log
    make >> "${STP_LOG}" 2>&1
else
    echo "No STP_VERSION given or empty"
    exit 1
fi

# Only show build output if something went wrong to keep log output short
if [ $? -ne 0 ]; then
    echo "Build error"
    cat "${STP_LOG}"
fi
