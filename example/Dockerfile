FROM debian:latest

RUN apt-get update && \
     apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind git python3-virtualenv python3-pip -y

WORKDIR /apps

RUN git clone --depth=1  https://github.com/openssl/openssl.git
RUN cd openssl && ./config enable-ssl-trace  && make -j`nproc` && make install

ENV LD_LIBRARY_PATH /usr/local/lib/:/usr/local/lib64/

RUN git clone --depth=1 https://github.com/open-quantum-safe/liboqs && \
    cmake -S liboqs -B liboqs/build  -DBUILD_SHARED_LIBS=ON && \
    cmake --build liboqs/build --parallel 8 && \
    cmake --build liboqs/build --target install

