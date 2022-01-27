# Installation Script - tested on a fresh install of Ubuntu 20.04.3 LTS as root (sudo)

# Show all commands being run
#set -x

# Error out if one fails
set -e

# Pull packages from apt
apt install -y python3-pip build-essential libssl-dev swig python3-dev

# Install Google Chrome
wget -O /tmp/google-chrome-stable_current_amd64.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
apt install -y /tmp/google-chrome-stable_current_amd64.deb

# Install required python packages
pip3 install -r requirements.txt
