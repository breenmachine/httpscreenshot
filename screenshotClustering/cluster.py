#!/usr/bin/python
import os
import sys
import argparse
from collections import OrderedDict
from collections import defaultdict
import re
import time
from bs4 import BeautifulSoup

try:
    from urllib.parse import quote,unquote
except:
    from urllib import quote,unquote

def addAttrToBag(attrName,url,link,wordBags,soup):
	for tag in soup.findAll('',{attrName:True}):
		if(isinstance(tag[attrName],str) or isinstance(tag[attrName],unicode)):
			tagStr = tag[attrName].encode('utf-8').strip()
		elif(isinstance(tag[attrName],list)):
			tagStr = tag[attrName][0].encode('utf-8').strip()
		else:
			print '[-] Strange tag type detected - '+str(type(tag[attrName]))
			tagStr = 'XXXXXXXXX'

		if(tagStr != ''):
			if(link):
				tagStr = linkStrip(tagStr)
			if(tagStr in wordBags[url]):
				wordBags[url][tagStr] += 1
			else:
				wordBags[url][tagStr] = 1

def addTagToBag(tagName,url,link,wordBags,soup):
	for tag in soup.findAll(tagName):
		if(tag is not None):
			tagStr = tag.string
			if(link):
				tagStr = linkStrip(tagStr)
			if(tagStr in wordBags[url]):
				wordBags[url][tagStr] += 1
			else:
				wordBags[url][tagStr] = 1

def linkStrip(linkStr):
	if(linkStr.find('/') != -1):
		linkStr = linkStr[linkStr.rfind('/'):]
	return linkStr

def createWordBags(htmlList):
	wordBags={}

	for f in htmlList:
		htmlContent = open(f,'r').read()
		wordBags[f]={}
		soup = BeautifulSoup(htmlContent)
		addAttrToBag('name',f,False,wordBags,soup)
		addAttrToBag('href',f,True,wordBags,soup)
		addAttrToBag('src',f,True,wordBags,soup)
		addAttrToBag('id',f,False,wordBags,soup)
		addAttrToBag('class',f,False,wordBags,soup)		
		addTagToBag('title',f,False,wordBags,soup)
		addTagToBag('h1',f,False,wordBags,soup)

	return wordBags

def getNumWords(wordBag):
	count = 0
	for value in wordBag.values():
		count = count+value
	return count

def computeScore(wordBag1,wordBag2,debug=0):
	commonWords = 0
	wordBag1Length = getNumWords(wordBag1)
	wordBag2Length = getNumWords(wordBag2)


	if(len(wordBag1) == 0 and len(wordBag2) == 0):
		if debug:
			print 'Both have no words - return true'
		return 1
	elif (len(wordBag1) == 0 or len(wordBag2) == 0):
		if debug:
			print 'One has no words - return false'
		return 0

	for word in wordBag1.keys():
		commonWords = commonWords+min(wordBag1[word],wordBag2.get(word,0))
	
	score = (float(commonWords)/float(wordBag1Length)*(float(commonWords)/float(wordBag2Length)))

	if debug:
		print "Common Words: "+str(commonWords)
		print "WordBag1 Length: "+str(wordBag1Length)
		print "WordBag2 Length: "+str(wordBag2Length)
		print score

	return score

def createClusters(wordBags,threshold):
	clusterData = {}
	i = 0
	siteList = wordBags.keys()
	for i in range(0,len(siteList)):
		clusterData[siteList[i]] = [threshold, i]

	for i in range(0,len(siteList)):
		for j in range(i+1,len(siteList)):
				score = computeScore(wordBags[siteList[i]],wordBags[siteList[j]])
				if (clusterData[siteList[i]][0] <= threshold and score > clusterData[siteList[i]][0]):
					clusterData[siteList[i]][1] = i
					clusterData[siteList[i]][0] = score
				if (clusterData[siteList[j]][0] <= threshold and score > clusterData[siteList[j]][0]):
					clusterData[siteList[j]][1] = i
					clusterData[siteList[j]][0] = score

	return clusterData

def getScopeHtml(scopeFile):
	if scopeFile is None:
		return None
	scope = open(scopeFile,'r')
	scopeText = '<br/><h3>Scope:</h3>'
	for line in scope.readlines():
		scopeText = scopeText + line+'<br/>'
	return scopeText

def renderClusterHtml(clust,width,height,scopeFile=None):
    html = ''
    scopeHtml = getScopeHtml(scopeFile)
    header = '''
    	<HTML>
    		<title>Web Application Catalog</title>
    		<BODY>
    			<h1>Web Application Catalog</h1>
    '''
    if(scopeHtml is not None):
    	header = header+scopeHtml
    header = header + '''
    			<script type="text/javascript" src="popup.js"></script>
    			<LINK href="style.css" rel="stylesheet" type="text/css">
    			<h3>Catalog:</h3>
    			'''
    html = html+'<table border="1">'
    
    for cluster,siteList in clust.iteritems():
        html=html+'<TR>'
        screenshotName = quote(siteList[0][0:-4], safe='./')
        html=html+'<TR><TD><img src="'+screenshotName+'png" width='+str(width)+' height='+str(height)+'/></TD></TR>'
        for site in siteList:
            screenshotName = quote(site[0:-5], safe='./')
            html=html+'<TD onmouseout="clearPopup()" onmouseover="popUp(event,\''+screenshotName+'.png\');"><a href="'+unquote(unquote(screenshotName[4:]).decode("utf-8")).decode("utf-8")+'">'+unquote(unquote(screenshotName[4:]).decode("utf-8")).decode("utf-8")+'</a></TD>'
        html=html+'</TR>'
    html=html+'</table>'
    footer = '</BODY></HTML>'

    return [header,html,footer]
def printJS():
	js = """
	function popUp(e,src)
	{
	    x = e.clientX;
	    y = e.clientY;

	    var img = document.createElement("img");
	    img.src = src;
	    img.setAttribute("class","popUp");
	    img.setAttribute("style","position:fixed;left:"+(x+15)+";top:"+0+";background-color:white");
	    //img.setAttribute("onmouseout","clearPopup(event)")
	    // This next line will just add it to the <body> tag
	    document.body.appendChild(img);
	}

	function clearPopup()
	{
	    var popUps = document.getElementsByClassName('popUp');
	    while(popUps[0]) {
	        popUps[0].parentNode.removeChild(popUps[0]);
	    }
	}
	"""

	f = open('popup.js','w')
	f.write(js)
	f.close()

def doCluster(htmlList):
	siteWordBags = createWordBags(htmlList)
	clusterData = createClusters(siteWordBags,0.6)

	clusterDict = {}
	for site,data in clusterData.iteritems():
		if data[1] in clusterDict:
			clusterDict[data[1]].append(site)
		else:
			clusterDict[data[1]]=[site]
	return clusterDict


'''For a diff report we want 3 sections:
1. New sites 
2. Removed sites
2. Changed sites
'''
def doDiff(htmlList,diffList):
	'''Find new sites - this is easy just find any html filenames that are present in diffDir
		and not htmlList'''
	newList=[]
	for newItem in diffList:
		found = False
		newItemName = newItem[newItem.rfind('/')+1:]
		for oldItem in htmlList:
			oldItemName = oldItem[oldItem.rfind('/')+1:]
			if(oldItemName == newItemName):
				found = True
				break;
		if(not found):
			newList.append(newItem)

	'''Now find items that were in the previous scan but not the new'''
	oldList=[]
	for oldItem in htmlList:
		found = False
		oldItemName = oldItem[oldItem.rfind('/')+1:]
		for newItem in diffList:
			newItemName = newItem[newItem.rfind('/')+1:]
			if(newItemName == oldItemName):
				found = True
				break;
		if(not found):
			oldList.append(oldItem)

	'''Now find items that changed between the two scans'''
	changedList=[]
	oldPath = htmlList[0][:htmlList[0].rfind('/')+1]
	newPath = diffList[0][:diffList[0].rfind('/')+1]

	for newItem in diffList:
		newItemName = newItem[newItem.rfind('/')+1:]
		oldItem = oldPath+newItemName
		if(os.path.isfile(oldItem)):
			compare = [newItem,oldItem]
			wordBags = createWordBags(compare)
			score = computeScore(wordBags[newItem],wordBags[oldItem])
			if(score < 0.6):
				changedList.append(newItem)

	return [newList,oldList,changedList]

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("-d","--dir",help='Directory containing HTML files')
	parser.add_argument("-dF","--diff",default=None,help='Directory containing HTML files from a previous run to diff against')
	parser.add_argument("-t","--thumbsize",default='200x200',help='Thumbnail dimensions (e.g: 200x200).')
	parser.add_argument("-o","--output",default='clusters.html',help='Specify the HTML output filename')
	parser.add_argument("-s","--scope",default=None,help='Specify a scope file to include in the HTML output report')

	args = parser.parse_args()
	#create a list of images
	path = args.dir

	if(path is None):
		parser.print_help()
		sys.exit(0)

	htmlList = []
	htmlRegex = re.compile('.*html.*')
	for fileName in os.listdir(path):
		if(htmlRegex.match(fileName)):
	    		htmlList.append(path+fileName)
	
	n = len(htmlList)


	width = int(args.thumbsize[0:args.thumbsize.find('x')])
	height = int(args.thumbsize[args.thumbsize.rfind('x')+1:])

	html = ''
	if(args.diff is not None):
		diffList = []
		for fileName in os.listdir(args.diff):
			if(htmlRegex.match(fileName)):
		    		diffList.append(args.diff+fileName)
		
		lists = doDiff(htmlList,diffList)

		newClusterDict = doCluster(lists[0])
		removedClusterDict = doCluster(lists[1])
		changedClusterDict = doCluster(lists[2])

		htmlList = renderClusterHtml(newClusterDict,width,height,scopeFile=args.scope)
		newClusterTable = htmlList[1]

		htmlList = renderClusterHtml(removedClusterDict,width,height,scopeFile=args.scope)
		oldClusterTable = htmlList[1]

		htmlList = renderClusterHtml(changedClusterDict,width,height,scopeFile=args.scope)
		changedClusterTable = htmlList[1]

		html = htmlList[0]
		html = html+"<h2>New Websites</h2>"
		html = html+newClusterTable
		html = html+"<h2>Deleted Websites</h2>"
		html = html+oldClusterTable
		html = html+"<h2>Changed Websites</h2>"
		html = html+changedClusterTable
		html = html+htmlList[2]

	else:
		clusterDict = doCluster(htmlList)
		htmlList = renderClusterHtml(clusterDict,width,height,scopeFile=args.scope)
		html = htmlList[0]+htmlList[1]+htmlList[2]

	f = open(args.output,'w')
	f.write(html)
	printJS()
	
