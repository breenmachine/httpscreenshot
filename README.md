# httpscreenshot

Readme and Use cases:

HTTPScreenshot is a tool for grabbing screenshots and HTML of large numbers of websites. The goal is for it to be both thorough and fast which can sometimes oppose each other.

Before getting into documentation - this is what I USUALLY use for options if I want to screenshot a bunch of sites:

  ./httpscreenshot.py -i \<gnmapFile\> -p -w 40 -a -vH

Notice there are a ton of worker threads (40). This can be problematic, I make up for failures that could have been a result of too many threads with a second run:

  ./httpscreenshot.py -i \<gnmapFile\> -p -w 5 -a -vH

YMMV

The options are as follows:

  -h, --help            show this help message and exit   
  -l LIST, --list LIST  List of input URLs   
  -i INPUT, --input INPUT   
                        nmap gnmap output file   
  -p, --headless        Run in headless mode (using phantomjs)   
  -w WORKERS, --workers WORKERS   
                        number of threads   
  -t TIMEOUT, --timeout TIMEOUT   
                        time to wait for pageload before killing the browser
  -v, --verbose         turn on verbose debugging   
  -a, --autodetect      Automatically detect if listening services are HTTP or
                        HTTPS. Ignores NMAP service detction and URL schemes.     
  -vH, --vhosts         Attempt to scrape hostnames from SSL certificates and  
                        add these to the URL queue   
  -dB DNS_BRUTE, --dns_brute DNS_BRUTE     
                        Specify a DNS subdomain wordlist for bruteforcing on 
                        wildcard SSL certs   
  -r RETRIES, --retries RETRIES   
                        Number of retries if a URL fails or timesout   

Some of the above options have non-obvious use-cases, so the following provides some more detail:

-l, --list -> Takes as input a file with a simple list of input URLs in the format "http(s)://\<URL\>"

-i, --input -> Takes a gnmap file as input. This includes masscan gnmap output.

-p, --headless -> I find myself using this option more and more. By default the script "drives" FireFox. As the number of threads increases this becomes really ugly - 20,30 FireFox windows open at once. This options uses "phantomjs" which doesn't have a GUI but will still do a decent job parsing javascript.

-w, --workers -> The number of threads to use. Increase for more speed. The list of input URL's is automatically shuffled to avoid hammering at IP addresses that are close to each other when possible. If you add too many threads, you might start seeing timeouts in responses - adjust for your network and machine.

-t TIMEOUT, --timeout -> How long to wait for a response from the server before calling it quits

-v, --verbose -> Will spit out some extra debugging output.

-a, --autodetect -> Without this option enabled, HTTPScreenshot will behave as follows:
    
    If a LIST of urls is specified as input, sites with scheme "http://" are treated as non-ssl and sites with scheme "https://" are treated as ssl-enabled

    For GNMAP input the script will scrape input and try to use any SSL detection performed by nmap. Unfortunately this is unreliable, nmap doesn't always like to tell you that something is SSL enabled. Further, masscan doesn't do any version or service detection.

    The -a or --autodetect option throws away all SSL hints from the input file and tries to detect on its own.

-vH, --vhosts -> Often when visiting websites by their IP address (e.g: https://192.168.1.30), we will receive a different page than expected or an error. This is because the site is expecting a certain "virtual host" or hostname instead of the IP address, sometimes a single HTTP server will respond with many different pages for different hostnames.

    For plaintext "http" websites, we can use reverse DNS, BING reverse IP search etc... to try and find the hostnames associated with an IP address. This is not currently a feature in HTTPScreenshot, but may be implemented later.

    For SSL enabled "https" sites, this can be a little easier. The SSL certificate will provide us with a hint at the domain name in the CN field. In the "subject alt names" field of the certificate, when it exists, we may get a whole list of other domain names potentially associated with this IP. Often these are in the form "*.google.com" (wildcard certificate) but sometimes will be linked to a single hostname only like "www.google.com"

    the -vH or --vhosts flag will, for each SSL enabled website extract the hostnames from the CN and subject alt names field, and add them to the list of URL's to be screenshotted. For wildcard certificates, the "*." part of the name is dropped.

-dB, --dns_brute -> Must use with -vH for it to make sense. This flag specifies a file containing a list of potential subdomains. For any wildcard certificate e.g: "*.google.com", HTTPScreenshot will try to bruteforce valid subdomains and add them to the list of URLs to be screenshotted.

-r, --retries -> Sometimes FireFox or ghostscript timeout when fetching a page. This could be due to a number of factors, sometimes you just have too many threads going, a network hiccup, etc. This specifies the number of times to "retry" a given host when it fails.



