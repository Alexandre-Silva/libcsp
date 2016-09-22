waf configure build install --install-csp \
    --enable-rdp --enable-hmac --enable-crc32 \
    --enable-if-ax25 --enable-if-kiss \
    --with-os=posix --with-driver-usart=linux \
    --with-loglevel=debug \
    --prefix=/usr/local
