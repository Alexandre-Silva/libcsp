args=( "$@" )

if [[ ${#args} -eq 0 ]]; then
    args=( configure build )
fi

waf ${args[@]} \
    --install-csp \
    --enable-rdp --enable-hmac --enable-crc32 \
    --enable-if-ax25 --enable-if-kiss \
    --with-os=posix --with-driver-usart=linux \
    --with-loglevel=debug \
    --prefix=/usr/local
