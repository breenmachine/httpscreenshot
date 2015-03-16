#!/usr/bin/python

'''
Installation on Ubuntu:
apt-get install python-requests python-m2crypto phantomjs
If you run into: 'module' object has no attribute 'PhantomJS'
then pip install selenium (or pip install --upgrade selenium)
'''

from selenium import webdriver
from urlparse import urlparse
from random   import shuffle
from PIL      import Image
from PIL      import ImageDraw
from PIL      import ImageFont
import multiprocessing
import Queue
import argparse
import sys
import traceback
import os.path
import requests
import ssl
import M2Crypto
import re
import time
import signal
import shutil
import hashlib


reload(sys)
sys.setdefaultencoding("utf8")


def timeoutFn(func, args=(), kwargs={}, timeout_duration=1, default=None):
    import signal

    class TimeoutError(Exception):
        pass

    def handler(signum, frame):
        raise TimeoutError()

    # set the timeout handler
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeout_duration)
    try:
        result = func(*args, **kwargs)
    except TimeoutError as exc:
        result = default
    finally:
        signal.alarm(0)

    return result


def addUrlsForService(host, urlList, servicesList, scheme):
	if(servicesList == None or servicesList == []):
		return
	for service in servicesList:
		state = service.findPreviousSibling("state")
		if(state != None and state != [] and state['state'] == 'open'):
			urlList.append(scheme+host+':'+str(service.parent['portid']))


def detectFileType(inFile):
	#Check to see if file is of type gnmap
	firstLine = inFile.readline()
	secondLine = inFile.readline()
	thirdLine = inFile.readline()

	#Be polite and reset the file pointer
	inFile.seek(0)

	if ((firstLine.find('nmap') != -1 or firstLine.find('Masscan') != -1) and thirdLine.find('Host:') != -1):
		#Looks like a gnmap file - this wont be true for other nmap output types
		#Check to see if -sV flag was used, if not, warn
		if(firstLine.find('-sV') != -1 or firstLine.find('-A') != -1):
			return 'gnmap'
		else:
			print("Nmap version detection not used! Discovery module may miss some hosts!")
			return 'gnmap'
	else:
		return None


def parseGnmap(inFile, autodetect):
	'''
	Parse a gnmap file into a dictionary. The dictionary key is the ip address or hostname.
	Each key item is a list of ports and whether or not that port is https/ssl. For example:
	>>> targets
	{'127.0.0.1': [[443, True], [8080, False]]}
	'''
	targets = {}
	for hostLine in inFile:
		currentTarget = []
		#Pull out the IP address (or hostnames) and HTTP service ports
		fields = hostLine.split(' ')
		ip = fields[1] #not going to regex match this with ip address b/c could be a hostname
		for item in fields:
			#Make sure we have an open port with an http type service on it
			if (item.find('http') != -1 or autodetect) and re.findall('\d+/open',item):
				port  = None
				https = False
				'''
				nmap has a bunch of ways to list HTTP like services, for example:
				8089/open/tcp//ssl|http
				8000/closed/tcp//http-alt///
				8008/closed/tcp//http///
				8080/closed/tcp//http-proxy//
				443/open/tcp//ssl|https?///
				8089/open/tcp//ssl|http
				Since we want to detect them all, let's just match on the word http
				and make special cases for things containing https and ssl when we
				construct the URLs.
				'''
				port = item.split('/')[0]

				if item.find('https') != -1 or item.find('ssl') != -1:
					https = True
				#Add the current service item to the currentTarget list for this host
				currentTarget.append([port,https])

		if(len(currentTarget) > 0):
			targets[ip] = currentTarget
	return targets


def setupBrowserProfile(headless):
	browser = None
	while(browser is None):
		try:
			if(not headless):
				fp = webdriver.FirefoxProfile()
				fp.set_preference("webdriver.accept.untrusted.certs",True)
				fp.set_preference("security.enable_java", False)
				fp.set_preference("webdriver.load.strategy", "fast");
				browser = webdriver.Firefox(fp)
			else:
				browser = webdriver.PhantomJS(service_args=['--ignore-ssl-errors=true','--ssl-protocol=tlsv1'], executable_path="phantomjs")
		except Exception as e:
			print e
			time.sleep(1)
			continue
	return browser


def writeImage(text, filename, fontsize=40, width=1024, height=200):
	image = Image.new("RGBA", (width,height), (255,255,255))
	draw = ImageDraw.Draw(image)
	font = ImageFont.truetype(os.path.dirname(os.path.realpath(__file__))+"/LiberationSerif-BoldItalic.ttf", fontsize)
	draw.text((10, 0), text, (0,0,0), font=font)
	image.save(filename)


def worker(urlQueue, tout, debug, headless, doProfile, vhosts, subs, extraHosts, tryGUIOnFail, smartFetch):
	if(debug):
		print '[*] Starting worker'
	
	browser = None
	try:
		browser = setupBrowserProfile(headless)

	except:
		print "[-] Oh no! Couldn't create the browser, Selenium blew up"
		exc_type, exc_value, exc_traceback = sys.exc_info()
		lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
		print ''.join('!! ' + line for line in lines)
		return

	while True:
		#Try to get a URL from the Queue
		if urlQueue.qsize() > 0:
			try:			
				curUrl = urlQueue.get(timeout=tout)
			except Queue.Empty:
				continue
			print '[+] '+str(urlQueue.qsize())+' URLs remaining'
			screenshotName = urlparse(curUrl[0]).netloc.replace(":", "-")
			if(debug):
				print '[+] Got URL: '+curUrl[0]
			if(os.path.exists(screenshotName+".png")):
				if(debug):
			 		print "[-] Screenshot already exists, skipping"
				continue
		else:
			if(debug):
				print'[-] URL queue is empty, quitting.'
				browser.quit()
			return

		try:
			if(doProfile):
				[resp,curUrl] = autodetectRequest(curUrl, timeout=tout, vhosts=vhosts, urlQueue=urlQueue, subs=subs, extraHosts=extraHosts)
			else:
				resp = doGet(curUrl, verify=False, timeout=tout, vhosts=vhosts, urlQueue=urlQueue, subs=subs, extraHosts=extraHosts)
			if(resp is not None and resp.status_code == 401):
				print curUrl[0]+" Requires HTTP Basic Auth"
				f = open(screenshotName+".html",'w')
				f.write(resp.headers.get('www-authenticate','NONE'))
				f.write('<title>Basic Auth</title>')
				f.close()
				writeImage(resp.headers.get('www-authenticate','NO WWW-AUTHENTICATE HEADER'),screenshotName+".png")
				continue
			elif(resp is not None):

                                resp_hash = hashlib.md5(resp.text).hexdigest()
				
                                if smartFetch and resp_hash in hash_basket:
                                	#We have this exact same page already, copy it instead of grabbing it again
                                        print "[+] Pre-fetch matches previously imaged service, no need to do it again!"
                                        shutil.copy2(hash_basket[resp_hash]+".html",screenshotName+".html")
                                        shutil.copy2(hash_basket[resp_hash]+".png",screenshotName+".png")
                                else:
					if smartFetch:
						hash_basket[resp_hash] = screenshotName

  					browser.set_window_size(1024, 768)
	  				browser.set_page_load_timeout((tout))
					old_url = browser.current_url
					browser.get(curUrl[0].strip())
					if(browser.current_url == old_url):
						print "[-] Error fetching in browser but successfully fetched with Requests: "+curUrl[0]
						if(headless):
							if(debug):
								print "[+] Trying with sslv3 instead of TLS - known phantomjs bug: "+curUrl[0]
							browser2 = webdriver.PhantomJS(service_args=['--ignore-ssl-errors=true'], executable_path="phantomjs")
							old_url = browser2.current_url
							browser2.get(curUrl[0].strip())
							if(browser2.current_url == old_url):
								if(debug):
									print "[-] Didn't work with SSLv3 either..."+curUrl[0]
								browser2.close()
							else:
								print '[+] Saving: '+screenshotName
								html_source = browser2.page_source
								f = open(screenshotName+".html",'w')
								f.write(html_source)
								f.close()
								browser2.save_screenshot(screenshotName+".png")
								browser2.close()
								continue						
	
						if(tryGUIOnFail and headless):
							print "[+] Attempting to fetch with FireFox: "+curUrl[0]
							browser2 = setupBrowserProfile(False)
							old_url = browser2.current_url
							browser2.get(curUrl[0].strip())
							if(browser2.current_url == old_url):
								print "[-] Error fetching in GUI browser as well..."+curUrl[0]
								browser2.close()
								continue
							else:
								print '[+] Saving: '+screenshotName
								html_source = browser2.page_source
								f = open(screenshotName+".html",'w')
								f.write(html_source)
								f.close()
								browser2.save_screenshot(screenshotName+".png")
								browser2.close()
								continue
						else:
							continue
	
					print '[+] Saving: '+screenshotName
					html_source = browser.page_source
					f = open(screenshotName+".html",'w')
					f.write(html_source)
					f.close()
					browser.save_screenshot(screenshotName+".png")
		except Exception as e:
			print e
			print '[-] Something bad happened with URL: '+curUrl[0]
			if(curUrl[2] > 0):
				curUrl[2] = curUrl[2] - 1;
				urlQueue.put(curUrl)
			if(debug):
				exc_type, exc_value, exc_traceback = sys.exc_info()
				lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
				print ''.join('!! ' + line for line in lines) 
			browser.quit()
			browser = setupBrowserProfile(headless)
			continue


def doGet(*args, **kwargs):
	url        = args[0]
	doVhosts   = kwargs.pop('vhosts'    ,None)
	urlQueue   = kwargs.pop('urlQueue'  ,None)
	subs       = kwargs.pop('subs'      ,None)
	extraHosts = kwargs.pop('extraHosts',None)

	kwargs['allow_redirects'] = False

	resp = requests.get(url[0],**kwargs)


	#If we have an https URL and we are configured to scrape hosts from the cert...
	if(url[0].find('https') != -1 and url[1] == True):
		#Pull hostnames from cert, add as additional URLs and flag as not to pull certs
		host = urlparse(url[0]).hostname
		port = urlparse(url[0]).port
		if(port is None):
			port = 443

		cert     = ssl.get_server_certificate((host,port),ssl_version=ssl.PROTOCOL_SSLv23)
		x509     = M2Crypto.X509.load_cert_string(cert)
		subjText = x509.get_subject().as_text()
		names    = re.findall("CN=([^\s]+)",subjText)

		try:
			altNames = x509.get_ext('subjectAltName').get_value()
			names.extend(re.findall("DNS:([^,]*)",altNames))
		except:
			pass

		for name in names:
			if(name.find('*.') != -1):
				for sub in subs:
					try:
						sub = sub.strip()
						hostname = name.replace('*.',sub+'.')
						if(hostname not in extraHosts):
							extraHosts[hostname] = 1
							address = socket.gethostbyname(hostname)
							urlQueue.put(['https://'+hostname+':'+str(port),False,url[2]])
							print '[+] Discovered subdomain '+address
					except:
						pass
				name = name.replace('*.','')
				if(name not in extraHosts):
					extraHosts[name] = 1
					urlQueue.put(['https://'+name+':'+str(port),False,url[2]])
					print '[+] Added host '+name

			else:
				if (name not in extraHosts):
					extraHosts[name] = 1
					urlQueue.put(['https://'+name+':'+str(port),False,url[2]])
					print '[+] Added host '+name
		return resp
	else:	
		return resp


def autodetectRequest(url, timeout, vhosts=False, urlQueue=None, subs=None, extraHosts=None):
	'''Takes a URL, ignores the scheme. Detect if the host/port is actually an HTTP or HTTPS
	server'''
	resp = None
	host = urlparse(url[0]).hostname
	port = urlparse(url[0]).port

	if(port is None):
		if('https' in url[0]):
			port = 443
		else:
			port = 80

	try:
		#cert = ssl.get_server_certificate((host,port))
		
		cert = timeoutFn(ssl.get_server_certificate,kwargs={'addr':(host,port),'ssl_version':ssl.PROTOCOL_SSLv23},timeout_duration=3)

		if(cert is not None):
			if('https' not in url[0]):
				url[0] = url[0].replace('http','https')
				#print 'Got cert, changing to HTTPS '+url[0]

		else:
			url[0] = url[0].replace('https','http')
			#print 'Changing to HTTP '+url[0]


	except Exception as e:
		url[0] = url[0].replace('https','http')
		#print 'Changing to HTTP '+url[0]
	try:
		resp = doGet(url,verify=False, timeout=timeout, vhosts=vhosts, urlQueue=urlQueue, subs=subs, extraHosts=extraHosts)
	except Exception as e:
		print 'HTTP GET Error: '+str(e)
		print url[0]

	return [resp,url]


def sslError(e):
	if('the handshake operation timed out' in str(e) or 'unknown protocol' in str(e) or 'Connection reset by peer' in str(e) or 'EOF occurred in violation of protocol' in str(e)):
		return True
	else:
		return False

def signal_handler(signal, frame):
        print "[-] Ctrl-C received! Killing Thread(s)..."
	sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

if __name__ == '__main__':
	parser = argparse.ArgumentParser()

	parser.add_argument("-l","--list",help='List of input URLs')
	parser.add_argument("-i","--input",help='nmap gnmap output file')
	parser.add_argument("-p","--headless",action='store_true',default=False,help='Run in headless mode (using phantomjs)')
	parser.add_argument("-w","--workers",default=1,type=int,help='number of threads')
	parser.add_argument("-t","--timeout",type=int,default=10,help='time to wait for pageload before killing the browser')
	parser.add_argument("-v","--verbose",action='store_true',default=False,help='turn on verbose debugging')
	parser.add_argument("-a","--autodetect",action='store_true',default=False,help='Automatically detect if listening services are HTTP or HTTPS. Ignores NMAP service detction and URL schemes.')
	parser.add_argument("-vH","--vhosts",action='store_true',default=False,help='Attempt to scrape hostnames from SSL certificates and add these to the URL queue')
	parser.add_argument("-dB","--dns_brute",help='Specify a DNS subdomain wordlist for bruteforcing on wildcard SSL certs')
	parser.add_argument("-r","--retries",type=int,default=0,help='Number of retries if a URL fails or timesout')
	parser.add_argument("-tG","--trygui",action='store_true',default=False,help='Try to fetch the page with FireFox when headless fails')
	parser.add_argument("-sF","--smartfetch",action='store_true',default=False,help='Enables smart fetching to reduce network traffic, also increases speed if certain conditions are met.')

	args = parser.parse_args()

	if(len(sys.argv) < 2):
		parser.print_help()
		sys.exit(0)

	if(args.input is not None):
		inFile = open(args.input,'r')
		if(detectFileType(inFile) == 'gnmap'):
			hosts = parseGnmap(inFile,args.autodetect)
			urls = []
			for host,ports in hosts.items():
				for port in ports:
					url = ''
					if port[1] == True:
						url = ['https://'+host+':'+port[0],args.vhosts,args.retries]
					else:
						url = ['http://'+host+':'+port[0],args.vhosts,args.retries]
					urls.append(url)
		else:
			print 'Invalid input file - must be Nmap GNMAP'
	
	elif (args.list is not None):
		f = open(args.list,'r')
		lst = f.readlines()
		urls = []
		for url in lst:
			urls.append([url.strip(),args.vhosts,args.retries])
	else:
		print "No input specified"
		sys.exit(0)
	

	#shuffle the url list
	shuffle(urls)

	#read in the subdomain bruteforce list if specificed
	subs = []
	if(args.dns_brute != None):
		subs = open(args.dns_brute,'r').readlines()

	#Fire up the workers
	urlQueue      = multiprocessing.Queue()
	manager       = multiprocessing.Manager()
	hostsDict     = manager.dict()
	workers       = []
	hash_basket   = {}

	for i in range(args.workers):
		p = multiprocessing.Process(target=worker, args=(urlQueue, args.timeout, args.verbose, args.headless, args.autodetect, args.vhosts, subs, hostsDict, args.trygui, args.smartfetch))
		workers.append(p)
		p.start()
	
	for url in urls:
		urlQueue.put(url)

	for p in workers:
	        p.join(.001)
			
