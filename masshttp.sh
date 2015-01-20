#!/bin/sh

/root/masscan/bin/masscan -p80,443 -iL networks.txt -oG http.gnmap --rate 100000
mkdir httpscreenshots
cd httpscreenshots
python ~/tools/httpscreenshot.py -i ../http.gnmap -p -t 30 -w 50 -a -vH -r 1
python ~/tools/httpscreenshot.py -i ../http.gnmap -p -t 10 -w 10 -a -vH
cd ..
python screenshotClustering/cluster.py -d httpscreenshots/

