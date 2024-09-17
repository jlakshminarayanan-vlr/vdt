#!/usr/bin/env python
"""
__author__ = "Keenan Matheny"
__credits__ = ["Keenan Matheny", "Christopher Morrow", "Fouad Sethna", "Kevin Hagopian"]
__license__ = "SPDX-License-Identifier: MIT"
__version__ = "1.0.0"
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
__title__ = "VMdir Check"
REQUIRED_SERVICE = "vmdird"

import os
import sys
import re
sys.path.append(os.environ['VMWARE_PYTHON_PATH'])
parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
libdir = os.path.join(parentdir, 'lib')
sys.path.append(os.path.abspath(libdir))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pformatting import *
from utils import getSingleServiceStatus, getStartup, Command, getDeployType, prompt
from vdt import setupLogging
import logging
logger = logging.getLogger(__name__)



def getRegValue(regtree, regkey):
	result = ""
	cmd = "/opt/likewise/bin/lwregshell list_values '%s'" % regtree
	query, errors, timeout = Command(cmd).run()
	for line in query.splitlines():
		line = line.replace('+',' ')
		if regkey in line:
			return line

def getPartnerStatus(username,password):
	title = "VMdir Status Check"
	logger.debug("Getting partner status with vdcrepadmin")
	msg = ""
	if username != "" and password != "":
		username = username.split('@')[0]
		cmd = ['/usr/lib/vmware-vmdir/bin/vdcrepadmin', '-f','showpartnerstatus','-h', 'localhost','-u', 'administrator', '-w',password]
		partnerstatus, errors, timeout  = Command(cmd).run()
		if partnerstatus.strip() == "":
			result = color_wrap("[INFO]", 'info')
			formResult(result, title + " (No partners)")
			# print("\tNo partners.")
		else:
			failflag = False
			for line in partnerstatus.splitlines():
				if 'Host available' in line:
					if 'No' in line:
						failflag = True
				if "Status available" in line:
					if 'No' in line:
						failflag = True
			if failflag:
				result = color_wrap("[FAIL]",'fail')
				msg = """
	If any partners are down, power them up and check again.  
	Otherwise, further investigation is needed.
	Reference internal KB article 78374.\n"""
			else:
				result = color_wrap("[PASS]",'pass')
			
			# print(partnerstatus)
			formResult("\n" + result, title)

			print("\n  Details:")
			for line in partnerstatus.splitlines():
				print("\t" + line)
			if msg != "":
				print(msg)	
	else:
		print("\tSkipped due to empty credentials")

def checkRegistry():
	title = "VMdir Arguments Check\n"
	result = color_wrap("[PASS]",'pass')
	msg = """\tPROBLEM:  If you have recently failed an upgrade or converge, 
	please run the following command and restart all services:

 /opt/likewise/bin/lwregshell set_value '[HKEY_THIS_MACHINE\Services\\vmdir]' "Arguments" "/usr/lib/vmware-vmdir/sbin/vmdird -s -l 0 -f /usr/lib/vmware-vmdir/share/config/vmdirschema.ldif"
	"""
	arg_reg = getRegValue("[HKEY_THIS_MACHINE\Services\\vmdir]","Arguments")
	if '-m standalone' in arg_reg:
		result = color_wrap("[FAIL]",'fail')
		formResult("\n" + result,title)
		print(msg)
	else:
		formResult("\n" + result,title)

def getVmdirState(username,password):
	username = username.split('@')[0]
	error_msg = ""
	title = "VMdir State Check"
	state, errors, timeout  = Command("/usr/lib/vmware-vmafd/bin/dir-cli state get --server-name localhost --login %s" % username, response = password).run()
	logger.debug("State = %s" % state)
	state = state.rsplit(":", 1)[1]
	if 'Normal' in state:
		result = color_wrap("[PASS]",'pass')
	else:
		result = color_wrap("[FAIL]",'fail') 
		error_msg = """
	VMDIR STATE IS: %s
	Please use /usr/lib/vmware-vmdir/bin/vdcadmintool option 6 to 
	confirm the state.  Check /var/log/vmware/vmdird/vmdird-syslog.log 
	to investigate.
	""" % state
	formResult("\n" + result,title)
	if error_msg != "":
		print(error_msg)

def getVmdirDatabaseSize():
	logger.debug("Getting size of data.mdb")
	datamdb = "/storage/db/vmware-vmdir/data.mdb"
	filesize = os.path.getsize(datamdb)
	filesize = filesize/(1024*1024)
	filesize = str(round(filesize,2)) + "MB"
	return filesize

def main(username,password):
	getPartnerStatus(username,password)
	getVmdirState(username,password)
	checkRegistry()

def main_wrap(username="", password=""):
	TITLE = "VMdir Check"
	# main(username,password)
	if getDeployType() != 'management':
		setupLogging()
		# TITLE = color_wrap(TITLE,'title')
		# print(TITLE)
		vmdirsize = getVmdirDatabaseSize()
		formResult(color_wrap("[INFO]",'info'),"VMdir database size: %s\n" % vmdirsize)
		req_service = REQUIRED_SERVICE
		service_status = getSingleServiceStatus(req_service)
		service_startup = getStartup(req_service)
		if service_status and service_startup == 'Automatic':
			main(username,password)
		elif service_status and service_startup != 'Automatic':
			print('Service: %s is disabled.' % req_service)
		elif not service_status and service_startup == 'Automatic':
			formResult(color_wrap("[FAIL]", 'fail'), "Service: %s is not started! It is required for this test to run." % req_service)
		else:
			formResult(color_wrap("[INFO]", 'info'), "Service: %s is not started.  Is it configured and running?" % req_service)

if __name__ == '__main__':
	if len(sys.argv) > 2:
		main_wrap(sys.argv[1], sys.argv[2])
	else:
		username,password = prompt()
		main_wrap(username,password)
