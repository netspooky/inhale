FROM python:slim-buster


COPY requirements.txt .

RUN  apt update && apt install --assume-yes apt-utils \
    && apt install --assume-yes wget git build-essential apt-transport-https procps automake libtool make gcc jq curl \
    # install elasticsearch
    && wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add - \
    && echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-7.x.list \
    && apt-get update && apt-get install --assume-yes elasticsearch \
    # install python dependencies
    && python3 -m pip install -r requirements.txt \
    # download radare2, yara, and binwalk
    && git clone https://github.com/radare/radare2 \
    && git clone https://github.com/ReFirmLabs/binwalk \
    && wget https://github.com/VirusTotal/yara/archive/v3.10.0.tar.gz \
    # install radare2
    && cd radare2 && sys/install.sh && cd / \
    # install yara
    && tar xvzf v3.10.0.tar.gz \
    && cd yara-3.10.0/ \
    && ./bootstrap.sh \
    && ./configure \
    && make \
    && make install && cd / \
    && sh -c 'echo "/usr/local/lib" >> /etc/ld.so.conf' && ldconfig \
    # install binwalk
    && cd binwalk \
    && python3 setup.py install \
    # clean up
    && cd / && rm -rf binwalk v3.10.0.tar.gz v3.10.0 \
    && apt purge --assume-yes wget git build-essential apt-transport-https automake make gcc apt-utils \
    && apt autoremove --assume-yes && apt clean
workdir /app