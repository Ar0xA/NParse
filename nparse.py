#Module to parse the XML data from Nessus and return it either into an ObjDict or Json string.

from bs4 import BeautifulSoup
from objdict import ObjDict
from dateutil.parser import parse
from datetime import timedelta
import time
import sys

def _parse_data(nessus_xml_data):

    #some quick report checking
    data = ObjDict()

    tmp_scanname = nessus_xml_data.report['name']
    if len(tmp_scanname) == 0:
        print ('Didn\'t find report name in file. is this a valid nessus file?')
        sys.exit(1)
    else:
        data.scanname = tmp_scanname

    #policyused
    data.scanpolicy = nessus_xml_data.policyname.get_text()

    # see if there are any hosts that are reported on
    hosts = nessus_xml_data.findAll('reporthost')
    if len(hosts) == 0:
        print ('Didn\'t find any hosts in file. Is this a valid nessus file?')
        sys.exit(1)
    else:
        print ('Found %i hosts' % (len(hosts)))

    #find the Task ID for uniqueness checking
    #test: is this unique per RUN..or per task?
    task_id = ""
    tmp_prefs = nessus_xml_data.findAll('preference')
    for pref in tmp_prefs:
        if "report_task_id" in str(pref):
            task_id = pref.value.get_text()

    for host in hosts:
        #lets iterate through the reportItem, here the compliance items will be
        reportItems = host.findAll('reportitem')
        for rItem in reportItems:
            host_info = ObjDict()
            #lets get the host information
            host_info.taskid= task_id

            host_info.hostname = host['name']
            host_info.hostip = host.find('tag', attrs={'name': 'host-ip'}).get_text()
            macaddress = host.find('tag', attrs={'name': 'mac-address'})
            if macaddress:
                host_info.hostmacaddress = macaddress.get_text()
            else:
                host_info.hostmacaddress = None

            credscan = host.find('tag', attrs={'name': 'Credentialed_Scan'})
            if credscan:
                 host_info.credentialedscan = credscan.get_text()
            else:
                host_info.credentialedscan = None

            host_info.hostscanstart = host.find('tag', attrs={'name': 'HOST_START'}).get_text()
            #convert to normal date format
            host_info.hostscanstart = parse(host_info.hostscanstart)
            #convert to UTC time
            timeoffset = int((time.localtime().tm_gmtoff)/3600)
            host_info.hostscanstart =host_info.hostscanstart - timedelta(hours=timeoffset)

            host_info.hostscanend = host.find('tag', attrs={'name': 'HOST_END'}).get_text()
            host_info.hostscanend = parse(host_info.hostscanend)
            host_info.hostscanend =  host_info.hostscanend - timedelta(hours=timeoffset)
            #host_info["@timestamp"] = host_info.hostscanend

            #fqdn might be optional
            host_fqdn = host.find('tag', attrs={'name': 'host-fqdn'})
            if host_fqdn:
                host_info.hostfqdn = host_fqdn.get_text()
            else:
                host_info.hostfqdn = None

            #get all report findings info
            try:
                #these fields should always be present
                host_info.severity = rItem['severity']
                host_info.port = rItem['port']
                host_info.svc_name = rItem['svc_name']
                host_info.protocol = rItem['protocol']
                host_info.pluginid = rItem['pluginid']
                host_info.pluginname = rItem['pluginname']
                host_info.plugintype = rItem.find('plugin_type').get_text()
                host_info.pluginfamily = rItem['pluginfamily']
                host_info.riskfactor = rItem.find('risk_factor').get_text()
                agent = rItem.find('agent')

                if agent:
                    host_info.agent = agent.get_text()
                else:
                    host_info.agent = None

                compliance_item = rItem.find('compliance')
                if compliance_item:
                    host_info.compliance = True
                else:
                    host_info.compliance = False

                #this stuff only around when its a compliance scan anyway
                host_info.compliancecheckname = None
                host_info.complianceauditfile = None
                host_info.complianceinfo = None
                host_info.complianceresult = None
                host_info.complianceseealso = None


                comaudit = rItem.find('cm:compliance-audit-file')
                if comaudit:
                    host_info.complianceauditfile =  comaudit.get_text()
                else:
                   host_info.complianceauditfile = None

                comcheck = rItem.find('cm:compliance-check-name')
                if comcheck:
                    host_info.compliancecheckname =  comcheck.get_text()
                else:
                   host_info.compliancecheckname = None

                cominfo = rItem.find('cm:compliance-info')
                if cominfo:
                    host_info.complianceinfo =  cominfo.get_text()
                else:
                   host_info.complianceinfo = None

                comsee = rItem.find('cm:compliance-see-also')
                if comsee:
                    host_info.complianceseealso =  comsee.get_text()
                else:
                   host_info.complianceseealso = None

                comref = rItem.find('cm:compliance-reference')

                if comref:
                    host_info.compliancereference = ObjDict()

                    compliancereference =  comref.get_text().split(",")
                    for ref in compliancereference:
                        comprefsplit = ref.split("|")
                        host_info.compliancereference[comprefsplit[0]] = ObjDict()
                        host_info.compliancereference[comprefsplit[0]] =comprefsplit[1]
                else:
                   host_info.compliancereference = None

                comres = rItem.find('cm:compliance-result')
                if comres:
                    host_info.complianceresult =  comres.get_text()
                else:
                   host_info.complianceresult = None

                descrip = rItem.find('description')
                if descrip:
                    host_info.description = descrip.get_text()
                else:
                    host_info.description = None

                synop = rItem.find('synopsis')
                if synop:
                    host_info.synopsis = synop.get_text()
                else:
                    host_info.synopsis = None

                solut = rItem.find('solution')
                if solut:
                    host_info.solution = solut.get_text()
                else:
                    host_info.solution = None

                plugin_output = rItem.find('plugin_output')
                if plugin_output:
                    host_info.pluginoutput = plugin_output.get_text()
                else:
                    host_info.pluginoutput = None

                expl_avail = rItem.find('exploit_available')
                if expl_avail:
                    host_info.exploitavailable = expl_avail.get_text()
                else:
                    host_info.exploitavailable = None

                expl_ease = rItem.find('exploitability_ease')
                if expl_ease:
                      host_info.exploitabilityease = expl_ease.get_text()
                else:
                      host_info.exploitabilityease = None

                cvss = rItem.find('cvss_base_score')
                if cvss:
                    host_info.cvssbasescore = cvss.get_text()
                else:
                    host_info.cvssbasescore = None

                cvss3 = rItem.find('cvss3_base_score')
                if cvss3:
                    host_info.cvss3basescore = cvss3.get_text()
                else:
                    host_info.cvss3basescore = None

                ppdate = rItem.find('patch_publication_date')
                if ppdate:
                    host_info.patchpublicationdate = parse(ppdate.get_text())
                else:
                    host_info.patchpublicationdate = None

                #these items can be none, one or many if found
                host_info.cve = []
                host_info.osvdb = []
                host_info.rhsa = []
                host_info.xref = []

                allcve = rItem.findAll('cve')
                if allcve:
                    for cve in allcve:
                        host_info.cve.append(cve.get_text())

                allosvdb = rItem.findAll('osvdb')
                if allosvdb:
                    for osvdb in allosvdb:
                        host_info.osvdb.append(osvdb.get_text())

                allrhsa = rItem.findAll('rhsa')
                if allrhsa:
                    for rhsa in allrhsa:
                        host_info.rhsa.append(rhsa.get_text())

                allxref = rItem.findAll('xref')
                if allxref:
                    for xref in allxref:
                        host_info.xref.append(xref.get_text())

                return host_info
            except Exception as e:
                print ("Error:")
                print (e)
                print (rItem)

def parse_to_json(nessus_xml_data):
    data = _parse_data(nessus_xml_data)
    return data.dumps()
	
def parse_to_dict(nessus_xml_data):
    data = _parse_data(nessus_xml_data)
	  return data
