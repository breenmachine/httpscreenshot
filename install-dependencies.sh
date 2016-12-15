# Installation Script - tested on an ubuntu/trusty64 vagrant box

# Show all commands being run
#set -x

# Error out if one fails
set -e

apt-get install -y swig swig3.0 libssl-dev python-dev libjpeg-dev xvfb

# Newer version in PyPI
#apt-get install -y python-requests

# Newer version in PyPI
#apt-get install -y python-m2crypto

# Installing pillow from PIP for the latest
#apt-get install -y python-pil

# Install pip and install pytnon requirements through it
apt-get install -y python-pip
pip install -r requirements.txt

# This binary is distributed with the code base, version is
# more recent then the one in the ubuntu repo (1.9.1 vs 1.9.0)
#apt-get install -y phantomjs

# Grab the latest of phantomjs it directly from the source
wget https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-2.1.1-linux-x86_64.tar.bz2

phantom_md5sum=`md5sum phantomjs-2.1.1-linux-x86_64.tar.bz2 | cut -d' ' -f1`
checksum="1c947d57fce2f21ce0b43fe2ed7cd361"

if [ "$phantom_md5sum" != "$checksum" ]
then
    echo "phantomjs checksum mismatch"
    exit 254
fi

tar xvf phantomjs-2.1.1-linux-x86_64.tar.bz2
mv phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/bin/phantomjs

wget https://github.com/mozilla/geckodriver/releases/download/v0.11.1/geckodriver-v0.11.1-linux64.tar.gz
tar xzvf geckodriver-v0.11.1-linux64.tar.gz
mv geckodriver /usr/bin/geckodriver
