FROM ubuntu:latest

MAINTAINER Keith Hoodlet <keith@attackdriven.io>

RUN mkdir -p /etc/httpscreenshot
WORKDIR /etc/httpscreenshot

COPY . /etc/httpscreenshot/

RUN apt-get update
RUN apt-get install -y wget libfontconfig vim

RUN ./install-dependencies.sh

RUN chmod +x httpscreenshot.py
RUN ln -s /etc/httpscreenshot/httpscreenshot.py /usr/bin/httpscreenshot

RUN mkdir -p /etc/httpscreenshot/images
WORKDIR /etc/httpscreenshot/images
