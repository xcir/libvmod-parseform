FROM ubuntu:bionic

RUN apt-get update && \
    apt-get install -y \
    curl \
    gnupg \
    apt-transport-https

RUN echo "deb https://packagecloud.io/varnishcache/varnish60lts/ubuntu/ bionic main" > /etc/apt/sources.list.d/varnishcache_varnish60lts.list \
    echo "deb-src https://packagecloud.io/varnishcache/varnish60lts/ubuntu/ bionic main" >> /etc/apt/sources.list.d/varnishcache_varnish60lts.list

RUN curl -L https://packagecloud.io/varnishcache/varnish60lts/gpgkey > key.txt && \
    apt-key add key.txt && \
    apt-get update

RUN apt-get install -y \
    libtool \
    automake \
    docutils-common \
    varnish-dev
