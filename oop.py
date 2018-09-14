import defusedxml.ElementTree as ET
import glob
import collections

class Vuln:
    def __init__(self, pluginID, firstDetection,lastDetection, name,\
        vulnDescription, remediation, severity, source):
    
        self.pluginID = pluginID
        self.firstDetection = firstDetection
        self.lastDetection = lastDetection
        self.name = name
        self.vulnDescription = vulnDescription
        self.remediation = remediation
        self.severity = severity
        self.source = source
        self.hosts = []

    def addHost(self, hostname):
        if not self.hasHost(hostname):
            self.hosts.append(hostname)
            
    def removeHost(self, hostname):
        if self.hasHost(hostname):
            self.hosts.remove(hostname)
    
    def hasHost(self, hostname):
        return self.hosts.count(hostname)

vulnList = []

'''def parseNessus(Nessus_file):
    
    root = ET.parse(Nessus_file).getroot()
    
    for host in root.findall('./Report/ReportHost'):
        
        affectedHost = host.attrib.get('name')
        print(affectedHost)
        
        for item in host.findall('./ReportItem'):
            if (item.attrib.get('pluginID') == '19506'\
                or item.attrib.get('severity') != '0'):'''
                    
def testParse(Nessus_file):
    #Load XML file for parsing
    root = ET.parse(Nessus_file).getroot()
    #Create object
    for plugin in root.findall('.//ReportItem'):
        #Filter out informational plugins
        if plugin.attrib.get('pluginID') == '19506'\
            or plugin.attrib.get('severity') != '0':
            #Get plugin description
            if plugin.find('./').tag == 'description':
                vulnDescription = plugin.text
            else: 
                vulnDescription = 'Failure'
            print(plugin.find('./').tag)
            print(vulnDescription)
            #Get plugin remediation
            if plugin.find('./').tag == 'solution':
                remediation = plugin.text
            else:
                remediation = 'Failure'
            #Set plugin severity
            if plugin.attrib.get('severity') == '1':
                severity = 'Low'
            elif plugin.attrib.get('severity') == '2':
                severity = 'Moderate'
            elif plugin.attrib.get('severity') == '3' or plugin.attrib.get('severity') == '4':
                severity = 'High'
            else:
                severity = 'Informational'
    
        #Create object
        tempVuln = Vuln(plugin.attrib.get('pluginID'),1/1/2018,2/1/2018,\
            plugin.attrib.get('name'), vulnDescription, remediation,\
            severity, 'Nessus')
        print(tempVuln.vulnDescription)

def secondTest(NessusFile):
    #Load MXL file for parsing
    root = ET.parse(NessusFile).getroot()
    #Create object
    for plugin in root.findall('.//ReportItem'):
        #Filter informational plugins
        if plugin.attrib.get('pluginID') == '19506'\
            or plugin.attrib.get('severity') != '0':
            pluginID = plugin.attrib.get('pluginID')
            #Get plugin information
            pluginName = plugin.find('plugin_name').text
            vulnDescription = plugin.find('synopsis').text
            remediation = plugin.find('solution').text
            #Get severity
            if plugin.find('risk_factor').text == 'Low':
                severity = 'Low'
            elif plugin.find('risk_factor').text == 'Medium':
                severity = 'Moderate'
            elif plugin.find('risk_factor').text == 'High' \
                or plugin.find('risk_factor').text == 'Critical':
                severity = 'High'
            else:
                severity = 'Informational'
            
            createPlugin(pluginID, 1/1/2018,2/1/2018,\
                pluginName, vulnDescription, remediation,\
                severity, 'Nessus')
            
def createPlugin(pluginID, firstDetection, lastDetection, pluginName,\
    vulnDescription, remediation, severity, source):
    #Create plugin
    pluginObj = Vuln(pluginID, firstDetection, lastDetection, pluginName,\
        vulnDescription, remediation, severity, source)
    

filePath = r'/home/mark/Documents/Python/Agent.nessus'
secondTest(filePath)

print('End')
