#!/usr/bin/env python
"""
__author__ = "Keenan Matheny"
__credits__ = ["Keenan Matheny", "Christopher Morrow", "Fouad Sethna", "Kevin Hagopian"]
__license__ = "SPDX-License-Identifier: MIT"
__status__ = "Beta"
__copyright__ = "Copyright (C) 2021 VMware, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of 
this software and associated documentation files (the "Software"), to deal in the 
Software without restriction, including without limitation the rights to use, 
copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the 
Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
__title__ = "Lookup Service Check"
import os
import sys
parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
libdir = os.path.join(parentdir, 'lib')
sys.path.append(os.path.abspath(libdir))
from utils import *
from lstool_scan import *
from lstool_parse import *
from utils import _getSslCert, get_params
from pformatting import *
import json
import logging
import xml.etree.ElementTree as xml
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vdt import setupLogging
import logging
logger = logging.getLogger(__name__)

def _setFilename(name, file_type):
	"""
	Sets filename in a helpful format
	
	Args:
		name (str): file name
		file_type (str): file extension
	
	Returns:
		str: string containing full file path.  compatible with windows and appliance
	"""
	file_name = str(time.strftime(name + file_type))
	path = logdir + '/' + file_name
	path = path.replace('\\','/')
	return path

class lsReport(object):

	"""
	Runs lstool_parse and lstool_scan to identify problems in the SSO domain.
	
	Attributes:
		report (json): this is the output of lstool_scan.py
		report_file (str): path to destination scan results file.
	"""

	def __init__(self, params, report_file):
		"""
		Args:
			params (dict): dictionary of local node parameters returned from 
			utils.get_params()
			report_file (str): path to destination scan results file.
		"""
		
		parser = LSTool_Parse()
		lsJsonData = parser.parseData()
		scanner = LSTool_Scan(lsJsonData)
		self.report = scanner.execute(live=True)
		self.report_file = report_file

	def generateReport(self):
		"""
		This function outputs the problems found (if any) and dumps the report to self.report_file
		"""
		result = ""
		for site in self.report:
			print("  SSO Site: " + site)
			for node in self.report[site]:
				
				output = self.report[site][node]['Problems Detected']
				if output != "No problems found.":
					result = "  " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC
					formResult(result, "Node: " + node)

					for problem in self.report[site][node]['Problems Detected']:
						if problem:
							issues = problem + ": " + self.report[site][node]['Problems Detected'][problem].get('Recommended Action')
							print("\t\t- PROBLEM: %s\n" % issues)
							if 'UNKNOWN' in node:
								print("\t\t- PROBLEM: 3rd party/Orphaned service registrations sometimes cause problems.  \n\t\tThese services need further investigation:\n")
								for service in self.report[site][node]['Services']:
									for x in self.report[site][node]['Services'][service]:
										# print(x.keys())
										if 'Service ID' in x.keys():
											# print()
											serviceid = x['Service ID']
											print("\t\t\tType: " + service + ", ID: " + serviceid)

				else:
					if 'UNKNOWN' in node:
						result = "  " + bcolors.WARNING + "[WARN]" + bcolors.ENDC
						formResult(result, "Node: " + node)
						print("\t\t- PROBLEM: 3rd party/Orphaned service registrations sometimes cause problems.  \n\t\tThese services need further investigation:\n")
						for service in self.report[site][node]['Services']:
							for x in self.report[site][node]['Services'][service]:
								# print(x.keys())
								if 'Service ID' in x.keys():
									# print()
									serviceid = x['Service ID']
									print("\t\t\tType: " + service + ", ID: " + serviceid)
						print("\n")
					else:		
						result = "  " + bcolors.OKGREEN + "[PASS]" + bcolors.ENDC
						formResult(result, "Node: " + node)


def getMachineIdFromVpxdCfg():
	try:
		vpxd = xml.parse("/etc/vmware-vpx/vpxd.cfg")
		sol_entry = vpxd.findall('.//name')
		vcsol = sol_entry[0].text
		vcsol = vcsol.replace('vpxd-','').split('@')[0]
	except:
		vcsol = "FAILED TO PARSE VPXD.CFG"
	return vcsol

def compareMachineID(vmafd_mid):
	print(color_wrap("MACHINE ID CHECK\n",'subheading'))
	vpxd_mid = getMachineIdFromVpxdCfg()
	result = "  " + bcolors.OKGREEN + "[PASS]" + bcolors.ENDC
	error = None
	if 'FAIL' in vmafd_mid:
		result = "  " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC
		msg = "Failed to get machine ID.  Is vmdir running?"
	else:
		if "FAILED" in vpxd_mid:
			result = "  " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC
			msg = "Failed to process the vpxd.cfg file!  Investigate the invalid XML"
		elif vmafd_mid != vpxd_mid:
			result = "  " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC
			rec_cmd = "/usr/lib/vmware-vmafd/bin/vmafd-cli set-machine-id --server-name localhost --id %s" % vpxd_mid
			msg = "Machine ID doesn't match vpxd.cfg (iKB# 71375)\n  Current MID: %s\n  Correct MID: %s\n  Recommended command (service restart required): \n\t%s" % (vmafd_mid, vpxd_mid, rec_cmd)
		else:
			msg = "Machine ID matches vpxd solution user in vpxd.cfg"
	formResult(result, msg)

def getDeployType():
	file = os.path.join(os.environ['VMWARE_CFG_DIR'],'deployment.node.type')
	with open(file) as fp:
		result = fp.read()
	return result

def main():
	
	warning = """Please remember to check if a node shows up in more than one SSO site.
If a node exists in more than one SSO site, you will need to run 
lsdoctor.py -r option 2 (https://kb.vmware.com/s/article/80469)
"""
	print(warning)

	try:
		params = get_params().get()
		if params['deploytype'] != 'infrastructure':
			compareMachineID(params['machineid'])
		try:
			report_name = str(time.strftime(str(socket.gethostname()) + "-%Y-%m-%d-%H%M%S"))
			output_file = _setFilename(report_name,'.json')
			print(color_wrap("\nREGISTRATION CHECK\n", 'subheading'))
			report = lsReport(params,output_file)
			report.generateReport()
		except:
			msg = "Failed to contact lookup service!"
			result = '  ' + color_wrap("[FAIL]",'fail')
			formResult(color_wrap(result,'fail'), msg)
			sys.exit(1)
	except Exception as e:
		print("ERROR:  %s Skipping lookup service check" % e)
		raise

if __name__ == '__main__':
	setupLogging()
	# print(color_wrap("Lookup Service Check", 'title'))

	if getDeployType().strip() != 'management':
		req_service = 'vmdird'
		service_status = getSingleServiceStatus(req_service)
		service_startup = getStartup(req_service)
		if service_status and service_startup == 'Automatic':
			main()
		elif service_status and service_startup != 'Automatic':
			print('Service: %s is disabled.' % req_service)
		elif not service_status and service_startup == 'Automatic':
			formResult(color_wrap("[FAIL]", 'fail'), "Service: %s is not started! It is required for this test to run." % req_service)
		else:
			formResult(color_wrap("[INFO]", 'info'), "Service: %s is not started.  Is it configured and running?" % req_service)
	else:
		main()


