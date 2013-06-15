Dependencies
------------

- [The LSAGS signature scheme](https://github.com/andres-erbsen/LSAGS)
- [`openssl`](https://www.openssl.org/)
- [`libcurl`](http://curl.haxx.se/libcurl/)
- [`libsmartcardpp`](https://code.google.com/p/esteid/downloads/list?can=2&q=smartcardpp&colspec=Filename+Summary+Uploaded+ReleaseDate+Size+DownloadCount)

Building
--------

### On Linux for Linux

    g++ -o voteclient voteclient.cpp -I /usr/include/PCSC/ -lcurl -ldl -lsmartcardpp -lcrypto -llsags

### On Linux for Windows

You will need mingw32 gcc and libraries, including the windows API files.
`sh windows/deps.sh` will download the external dependencies to `$HOME/mingw32`. You'll probably need to tweak some variables in the beginning of the script. `sh windows/build.sh` downloads and builds LSAGS and this.

If you'd like a binary, there might be one at <http://andres.tedx.ee/voteclient.exe> and it even might be recent.

License
-------

GPLv3 but not religious about it. 

The exception that allows linking to OpenSSL is in effect. If you are a non-GPL open source project and would like to use the code, contact me about it.
