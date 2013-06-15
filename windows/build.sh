prefix=$HOME/mingw32
host=i486-mingw32

cd $prefix

if test -d LSAGS
then
  cd LSAGS
  git pull
else
  git clone git://github.com/andres-erbsen/LSAGS
  cd LSAGS
fi
$host-gcc -c -O3 keccak/KeccakF-1600-opt32.c -o keccak/KeccakF-1600-opt32.o
$host-gcc -c -O3 keccak/KeccakSponge.c -o keccak/KeccakSponge.o
$host-gcc -c -O3 -I$prefix/include lsags.c -o lsags.o
$host-ar r liblsags.a lsags.o keccak/KeccakSponge.o keccak/KeccakF-1600-opt32.o
cp liblsags.a $prefix/lib/liblsags.a
cp lsags.h $prefix/include/lsags.h
cd ..

if test -d voteclient
then
  cd voteclient
  git pull
else
  git clone git://github.com/andres-erbsen/voteclient
  cd voteclient
fi
source $prefix/lib/libcurl.la
$host-g++ -o voteclient.exe voteclient.cpp -static-libgcc -static-libstdc++ -DCURL_STATICLIB -I$prefix/include -L$prefix/lib -lcurl -lsmartcardpp -lcrypto -llsags $inherited_linker_flags $dependency_libs -lversion -lgdi32
