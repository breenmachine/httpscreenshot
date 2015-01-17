#!/usr/bin/python

import sys, os
import re

def addUrlsForService(host,urlList,servicesList,scheme):
	if(servicesList == None or servicesList == []):
		return
	for service in servicesList:
		state = service.findPreviousSibling("state")
		if(state != None and state != [] and state['state'] == 'open'):
			urlList.append(scheme+host+':'+str(service.parent['portid']))

def parseGnmap(inFile):
	targets = {}
	for hostLine in inFile:
		currentTarget = []
		#Pull out the IP address (or hostnames) and HTTP service ports
		fields = hostLine.split(' ')
		ip = fields[1] #not going to regex match this with ip address b/c could be a hostname
		for item in fields:
			#Make sure we have an open port with an http type service on it
			if item.find('http') != -1 and re.findall('\d+/open',item):
				port = None
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

def detectFileType(inFile):
	#Check to see if file is of type gnmap
	firstLine = inFile.readline()
	secondLine = inFile.readline()
	thirdLine = inFile.readline()

	#Be polite and reset the file pointer
	inFile.seek(0)

	if (firstLine.find('nmap') != -1 and thirdLine.find('Host:') != -1):
		#Looks like a gnmap file - this wont be true for other nmap output types
		#Check to see if -sV flag was used, if not, warn
		if(firstLine.find('-sV') != -1 or firstLine.find('-A') != -1):
			return 'gnmap'
		else:
			print("Nmap version detection not used! Discovery module may miss some hosts!", LOG.INFO)
			return 'gnmap'
	else:
		return None

def main():
	if(sys.argv[1] is not None):
		inFile = open(sys.argv[1],'r')
		if(detectFileType(inFile) == 'gnmap'):
			hosts = parseGnmap(inFile)
			urls = []
			for host,ports in hosts.items():
				for port in ports:
					url=''
					if port[1] == True:
						url = 'https://'+host+':'+port[0]
					else:
						url = 'http://'+host+':'+port[0]
					urls.append(url)


		else:
			print 'Invalid input file - must be Nmap GNMAP'
	for url in urls:
		print url

def usage():
	print "Usage: %s <nmap gnmap>" % sys.argv[0]

if __name__ == '__main__':
        try:
                main()
        except Exception, e:
                print "Unable to run Main:", e
                sys.exit(1)