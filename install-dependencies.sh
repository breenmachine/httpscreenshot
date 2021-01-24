# Installation Script - tested on an ubuntu/trusty64 vagrant box

# Show all commands being run
#set -x

# Error out if one fails
set -e

apt-get install -y swig swig3.0 libssl-dev python3-dev libjpeg-dev xvfb firefox firefox-geckodriver

# Newer version in PyPI
#apt-get install -y python-requests

# Newer version in PyPI
#apt-get install -y python-m2crypto

# Installing pillow from PIP for the latest
#apt-get install -y python-pil

# Install pip and install pytnon requirements through it
apt-get install -y python3-pip
pip3 install -r requirements.txt
