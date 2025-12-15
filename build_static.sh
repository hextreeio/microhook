#!/bin/bash
set -e

docker build -t microhook-build .

# Use -t only if we have a TTY
DOCKER_TTY=""
if [ -t 0 ]; then
    DOCKER_TTY="-it"
fi

docker run $DOCKER_TTY --rm -v `pwd`:/qemu microhook-build /bin/bash -c '
    source $HOME/.cargo/env
    export PKG_CONFIG_PATH="/opt/python-static/lib/pkgconfig:$PKG_CONFIG_PATH"
    
    # Clean previous build
    rm -rf build
    
    ./configure \
        --static
    
    make -j$(nproc)
    make install
    rm -rf /opt/python-static
'
