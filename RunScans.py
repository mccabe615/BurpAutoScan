# Created by Carrie Roberts of Black Hills Information Security
# RunScans.py Version 2.1
# Released under GPL Version 2 License.
# August 20, 2015

import json
import sys
from subprocess import call
import datetime
import time

class m:
    @classmethod
    def log(self, logStr):
        print str(time.time()) + " " + logStr
        return

if len(sys.argv)==2:
    configFile = sys.argv[1]
else:
    configFile="config.json"
try:
    json_data=open(configFile)
    config=json.load(json_data)
except: # catch *all* exceptions
   e = sys.exc_info()[0]
   m.log( "There is a problem with the Configuration File 'config.json' that should be located in the same directory as this script: %s" % e )
   sys.exit()
json_data.close()
burpConfigs=config["burpConfigs"][0]
fileLocations=config["fileLocations"][0]

runBurp = True
runNikto = False

timeStamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

for site in config["sites"]:
    niktoReportFile = fileLocations["reportOutputPath"] + timeStamp + '_Nikto_' + site["protocol"] + '_' + site["fqdn"] + '_' + str(site["port"]) + '.htm'
    burpReportFile = fileLocations["reportOutputPath"] + timeStamp + '_Burp_' + site["protocol"] + '_' + site["fqdn"] + '_' + str(site["port"]) + '.html'
    burpStateFile = fileLocations["reportOutputPath"] + timeStamp + '_BurpState_' + site["protocol"] + '_' + site["fqdn"] + '_' + str(site["port"])
    if runBurp:
        cmd = "java -jar -Xmx" + burpConfigs["memory"] + " -Djava.awt.headless=" \
        + str(burpConfigs["headless"]) + " " + fileLocations["burpJar"] + " " + \
        site["protocol"] + " " + site["fqdn"] + " " + str(site["port"]) + " " + \
        site["path"] + " " + burpReportFile + " " + site["sessionToLoad"] + " " + burpStateFile
        m.log("Burp Command: " + cmd)
        return_code = call(cmd, shell=True)
        if return_code:
            m.log("Burp did not run successfully for site: " + site["fqdn"])
    else:
        m.log( "Not running Burp this time! site: " + site["siteName"])
    if runNikto:
        niktoCmd = fileLocations["nikto"] + " -h " + site["fqdn"] + " -p " + str(site["port"]) \
        + " -useragent \"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:33.0) Gecko/20100101 Firefox/33.0\"" \
        + " -output " + "\"" + niktoReportFile + "\""
        m.log( "Nikto Command: " + niktoCmd)
        return_code = call(niktoCmd, shell=True)
        if return_code:
            m.log( "Nikto did not run successfully for site: " + site["fqdn"])
    else:
        m.log( "Not running Nikto this time! site: " + site["siteName"])
m.log("!!!!!!!!!!!!!DONE!!!!!!!!!!!!!!")


