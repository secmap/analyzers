FROM ubuntu:14.04
MAINTAINER Chiawei Wang <glacier314@gmail.com>

RUN sed -i.bak "s/archive.ubuntu.com/ubuntu.cs.nctu.edu.tw/g" /etc/apt/sources.list
RUN apt-get update && apt-get install -y  \
        build-essential \
        git             \
        python          \
        pkg-config      \
        zlib1g-dev      \
        libglib2.0-dev  \
        libpixman-1-dev \
        automake        \
        autopoint       \
        libtool         \
        flex            \
        byacc           \
        cabextract      \
        curl            \
        expect          \
        python3-pip     \
        vim             \
        software-properties-common
RUN apt-add-repository -y ppa:brightbox/ruby-ng && \
    apt update                                  && \
    apt install -y ruby2.3 ruby2.3-dev
RUN pip3 install pexpect            && \
    gem install redis               && \
    gem install cassandra-driver    && \
    gem install docker-api          && \
    gem install sys-filesystem

ADD mba /root/mba/
ADD gv.json /root/
ADD ds.json /root/
ADD dba_config /root/
ADD win10.qcow2 /root/
ADD run-mba.sh /root/
ADD mba-tcl.py /root/
ADD analyze /

RUN cd /root/mba/ && \
    ./configure --target-list=x86_64-softmmu --enable-mba-all --disable-sdl --disable-kvm && \
    make clean && \
    make -j8
