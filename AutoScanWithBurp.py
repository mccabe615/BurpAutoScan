# This is a modification of the carbonator extension originally
# created by Blake Cornell of Integris Security LLC
# Released under GPL Version 2 license.
#
# Modifications were made by Carrie Roberts of Black Hills Information Security
# August 20, 2015
# BHISAutoScan.py Version 2.1

from burp import IBurpExtender
from burp import IHttpListener
from burp import IScannerListener
from java.net import URL
from java.io import File
import datetime
import time

class BurpExtender(IBurpExtender, IHttpListener, IScannerListener):
    def registerExtenderCallbacks(self, callbacks):
	self._callbacks = callbacks
	self._callbacks.setExtensionName("AutoScanWithBurp")
	self._helpers = self._callbacks.getHelpers()
	self.clivars = None

	self.spider_results=[]
	self.scanner_results=[]
	self.packet_timeout=5

	if not self.processCLI():
            self.log("No CLI's")
	    return None
	else:
            self.log("Processing CLI's")
	    self.clivars = True

        self.log( "loading state . . .")
	fileName = self.sessionToLoad
	self._callbacks.restoreState(File(fileName))
	self.log( "Done loading state")

	self.log( "Initiating BHISAutoScan Against: " + str(self.url))

        self.last_packet_seen= int(time.time()) #initialize the start of the spider/scan
	#add to scope if not already in there.
	if self._callbacks.isInScope(self.url) == 0:
		self._callbacks.includeInScope(self.url)
	#added to ensure that the root directory is scanned
	base_request = str.encode(str("GET "+self.path+" HTTP/1.1\nHost: "+self.fqdn+"\n\n"))
	if(self.scheme == 'https'):
		self._callbacks.doActiveScan(self.fqdn,self.port,1,base_request)
	else:
		self._callbacks.doActiveScan(self.fqdn,self.port,0,base_request)
	self._callbacks.sendToSpider(self.url)
	self._callbacks.registerHttpListener(self)
	self._callbacks.registerScannerListener(self)

	while int(time.time())-self.last_packet_seen <= self.packet_timeout:
		time.sleep(1)
	self.log( "No packets seen in the last " + str(self.packet_timeout) + " seconds.")
	self.log( "Removing Listeners")
	self._callbacks.removeHttpListener(self)
	self._callbacks.removeScannerListener(self)

	self.log( "Generating Report")
	self.generateReport('HTML')
	self.log( "Report Generated")
	self.log( "Closing Burp in " + str(self.packet_timeout) + " seconds.")
	time.sleep(self.packet_timeout)

	self.log( "Saving state for later review: " + self.sessionToSave)
	self._callbacks.saveState(File(self.sessionToSave))
	self.log( "done saving state")

	if self.clivars:
	    self._callbacks.exitSuite(False)
		
	return

    def processHttpMessage(self, tool_flag, isRequest, current):

	self.last_packet_seen = int(time.time())
	if tool_flag == self._callbacks.TOOL_SPIDER and isRequest: #if is a spider request then send to scanner
		self.spider_results.append(current)
		self.log("Sending new URL to Vulnerability Scanner: URL # " + str(len(self.spider_results)))
                if self.scheme == 'https':
			self._callbacks.doActiveScan(self.fqdn,self.port,1,current.getRequest()) #returns scan queue, push to array
		else:
			self._callbacks.doActiveScan(self.fqdn,self.port,0,current.getRequest()) #returns scan queue, push to array
	return

    def newScanIssue(self, issue):
	self.scanner_results.append(issue)
	self.log( "New issue identified: Issue # " + str(len(self.scanner_results)))
	return

    def generateReport(self, format):
	if format != 'XML':
		format = 'HTML'	
	self._callbacks.generateScanReport(format,self.scanner_results,File(self.reportFile))

	time.sleep(5)
	return

    def processCLI(self):
	cli = self._callbacks.getCommandLineArguments()
	if len(cli) < 0:
		self.log( "Incomplete target information provided.")
		return False
	elif not cli:
		self.log( "Extension loaded.")
		return False
	elif cli[0] == 'https' or cli[0] == 'http': #cli[0]=scheme,cli[1]=fqdn,cli[2]=port,cli[3]=path,cli[4]=reportFile,cli[5]=sessionToLoad,cli[6]=sessionToSave
		self.scheme = cli[0]
		self.fqdn = cli[1]
		self.port = int(cli[2])
		if len(cli) == 3:
			self.path = '/'
		elif len(cli) >= 4:
			self.path = cli[3]
			self.reportFile = cli[4]
			self.sessionToLoad = cli[5]
			self.sessionToSave = cli[6]			
		else:
			self.log( "Unknown number of CLI arguments")
			return False
		self.url = URL(self.scheme,self.fqdn,self.port,self.path)
	else:
		self.log( "Invalid command line arguments supplied")
		return False
	return True

    def log(self, logStr):
        print str(time.time()) + " " + logStr
        return
    
