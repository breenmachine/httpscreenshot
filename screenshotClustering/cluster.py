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
		soup = BeautifulSoup(htmlContent, 'html.parser')
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

def getPageTitle(htmlFile):
	"""Simple function to yank page title from html"""
	with open(htmlFile, 'r') as f:
		soup = BeautifulSoup(f, "lxml")
	try:
		return soup.title.string.encode('ascii', 'ignore')
	except AttributeError:
		return "No Page Title Found"

def renderClusterHtml(clust,width,height,scopeFile=None):
	html = ''
	scopeHtml = getScopeHtml(scopeFile)
	header = '''
	<HTML>
		<title>Web Application Catalog</title>
		<BODY>
	'''
	if(scopeHtml is not None):
		header = header+scopeHtml
	header = header + '''
		<script type="text/javascript" src="popup.js"></script>
		<LINK href="style.css" rel="stylesheet" type="text/css">
		<div class="table-title">
	        <h3>Web Application Catalog:</h3>
        </div>
		'''
	for cluster, siteList in clust.items():
		html = html + """
			<table class="table-fill">
			<thead>
				<TR>
					<th class="text-left" colspan="2">
						""" + getPageTitle(siteList[0]) + """ </th>
				</TR>
			</thead>
				<TR>
			"""
		screenshotName = quote(siteList[0][0:-4], safe='./')
		html = html + '<TD> <img src="'+screenshotName+'png" width='+str(width)+' height='+str(height)+'/></TD><TD>'
		for site in siteList:
			screenshotName = quote(site[0:-5], safe='./')
			if site != siteList[-1]:
				html = html + '<div onmouseout="clearPopup()" onmouseover="popUp(event,\''+screenshotName+'.png\');"><a href="'+unquote(unquote(screenshotName[2:]).decode("utf-8")).decode("utf-8")+'">'+unquote(unquote(screenshotName[2:]).decode("utf-8")).decode("utf-8")+'</a><br /></div>'
			else:
				html = html + '<div onmouseout="clearPopup()" onmouseover="popUp(event,\''+screenshotName+'.png\');"><a href="'+unquote(unquote(screenshotName[2:]).decode("utf-8")).decode("utf-8")+'">'+unquote(unquote(screenshotName[2:]).decode("utf-8")).decode("utf-8")+'</a></div> </TD></TR></table>'


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

def printCSS():
	css = """
	@import url(http://fonts.googleapis.com/css?family=Roboto:400,500,700,300,100);

	body {
		background-color: #3e94ec;
		font-family: "Roboto", helvetica, arial, sans-serif;
		font-size: 16px;
		font-weight: 400;
		text-rendering: optimizeLegibility;
	}

	div.table-title {
		display: block;
		margin: auto;
		max-width: 600px;
		padding:5px;
		width: 100%;
	}

	.table-title h3 {
		color: #fafafa;
		font-size: 30px;
		font-weight: 400;
		font-style:normal;
		font-family: "Roboto", helvetica, arial, sans-serif;
		text-shadow: -1px -1px 1px rgba(0, 0, 0, 0.1);
		text-transform:uppercase;
	}


	/*** Table Styles **/

	.table-fill {
		background: white;
		border-radius:3px;
		border-collapse: collapse;
		height: 320px;
		margin: auto;
		margin-bottom: 50px;
		max-width: 600px;
		padding:5px;
		width: 100%;
		box-shadow: 0 5px 10px rgba(0, 0, 0, 0.1);
		animation: float 5s infinite;
	}

	th {
		color:#D5DDE5;;
		background:#1b1e24;
		border-bottom:4px solid #9ea7af;
		border-right: 1px solid #343a45;
		font-size:23px;
		font-weight: 100;
		padding:24px;
		text-align:left;
		text-shadow: 0 1px 1px rgba(0, 0, 0, 0.1);
		vertical-align:middle;
	}

	th:first-child {
		border-top-left-radius:3px;
	}

	th:last-child {
		border-top-right-radius:3px;
		border-right:none;
	}

	tr {
		border-top: 1px solid #C1C3D1;
		border-bottom-: 1px solid #C1C3D1;
		color:#666B85;
		font-size:16px;
		font-weight:normal;
		text-shadow: 0 1px 1px rgba(256, 256, 256, 0.1);
	}

	tr:hover td {
		background:#4E5066;
		color:#FFFFFF;
		border-top: 1px solid #22262e;
		border-bottom: 1px solid #22262e;
	}

	tr:first-child {
		border-top:none;
	}

	tr:last-child {
		border-bottom:none;
	}

	tr:nth-child(odd) td {
		background:#EBEBEB;
	}

	tr:nth-child(odd):hover td {
		background:#4E5066;
	}

	tr:last-child td:first-child {
		border-bottom-left-radius:3px;
	}

	tr:last-child td:last-child {
		border-bottom-right-radius:3px;
	}

	td {
		background:#FFFFFF;
		padding:20px;
		text-align:left;
		vertical-align:middle;
		font-weight:300;
		font-size:18px;
		text-shadow: -1px -1px 1px rgba(0, 0, 0, 0.1);
		border-right: 1px solid #C1C3D1;
	}

	td:last-child {
		border-right: 0px;
	}

	th.text-left {
		text-align: left;
	}

	th.text-center {
		text-align: center;
	}

	th.text-right {
		text-align: right;
	}

	td.text-left {
		text-align: left;
	}

	td.text-center {
		text-align: center;
	}

	td.text-right {
		text-align: right;
	}
	"""
	f = open('style.css','w')
	f.write(css)
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
	printCSS()
	
