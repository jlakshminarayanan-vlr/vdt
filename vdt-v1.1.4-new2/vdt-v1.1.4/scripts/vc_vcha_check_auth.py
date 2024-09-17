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
__title__ = "VCHA CHECK"
import sys
import os
parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
libdir = os.path.abspath(os.path.join(parentdir, 'lib'))
sys.path.append(libdir)
from pformatting import *
sys.path.append(os.environ['VMWARE_PYTHON_PATH'])
from pyVim.connect import SmartConnect
from pyVmomi import Vim, VmomiSupport, vmodl
import ssl
import subprocess
from utils import prompt, getSingleServiceStatus, getStartup, get_params
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vdt import setupLogging
import logging
logger = logging.getLogger(__name__)

_DefaultCommmandEncoding = sys.getfilesystemencoding()

def run_command(cmd, stdin=None, quiet=False, close_fds=False,
				encoding=_DefaultCommmandEncoding, log_command=True):

	process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
							stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	if sys.version_info[0] >= 3 and isinstance(stdin, str):
		stdin = stdin.encode(encoding)
	stdout, stderr = process.communicate(stdin)
	return stdout

def getHostname():
	cmd = ['/usr/bin/hostname', '-f']
	return run_command(cmd).decode().strip()

class getVcha(object):
	
	def __init__(self, hostname, username, password):
		context = ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		try:
			self.c = SmartConnect(host=hostname, user=username, pwd=password,sslContext=context)
		except Exception as e:
			print("Failed to connect to %s.  Is the server currently failing over?" % hostname)
			sys.exit(1)
		self.vcha = self.c.content.failoverClusterManager
	
	def is_enabled(self):
		vcha_mode = False
		try:
			vcha_mode = self.vcha.getClusterMode()
		except:
			pass
		return vcha_mode

	def health(self):
		result = color_wrap("\n[PASS]",'pass')
		if self.is_enabled():
			alarms = []
			msg = "VCHA Health Status"
			
			cluster_health = self.vcha.GetVchaClusterHealth()
			health_Messages = cluster_health.healthMessages

			runtime_info = cluster_health.runtimeInfo

			mode = runtime_info.clusterMode
			mode = mode.upper()
			if mode != 'ENABLED':
				moderesult = color_wrap("[" + mode + "]",'warn')
			else:
				moderesult = color_wrap("[" + mode + "]",'pass')
			formResult("\t" + moderesult,"Cluster Mode")
			
			state = runtime_info.clusterState
			state = state.upper()
			if state != 'HEALTHY':
				stateresult = color_wrap("[" + state + "]",'fail')
				result = color_wrap("\n[FAIL]", 'fail')
				for health_data in health_Messages:
					alarms.append(health_data.message)
					
			else:
				stateresult = color_wrap("[" + state + "]",'pass')
			formResult("\t" + stateresult,'Cluster State')
			if len(alarms) > 0:
				for alarm in alarms:
					formResult("\t" + color_wrap('DETAIL','warn'), alarm)

			node_info = runtime_info.nodeInfo
			print("\nVCHA Node information:")
			for node in node_info:
				noderesult = color_wrap("[PASS]",'pass')

				if node.nodeState == 'up':
					nodestatus = '\t' + node.nodeRole + " - " + node.nodeIp + " - " + color_wrap(node.nodeState,'pass')
				else:
					noderesult = color_wrap("[FAIL]", 'fail')
					result = color_wrap("\n[FAIL]", 'fail')
					nodestatus = '\t' + node.nodeRole + " - " + node.nodeIp + " - " + color_wrap(node.nodeState,'fail')
				formResult(noderesult,nodestatus)
			formResult(result,msg)
		else:
			print('VCHA is not enabled.')

def getDeployType():
	file = os.path.join(os.environ['VMWARE_CFG_DIR'],'deployment.node.type')
	with open(file) as fp:
		result = fp.read()
	return result

def main(username="",password=""):
	if getDeployType() != 'infrastructure':
		# username, password = prompt()
		if username != "" and password != "":
			vcha = getVcha(getHostname(), username, password)
			vcha.health()

def main_wrap(username="", password=""):
	setupLogging()
	dtype = getDeployType().strip()
	if 'infrastructure' not in dtype:
		# print(color_wrap("VCHA CHECK",'title'))
		req_service = 'vmware-vcha'
		service_status = getSingleServiceStatus(req_service)
		service_startup = getStartup(req_service)
		if service_status and service_startup == 'Automatic':
			main(username,password)
		elif service_status and service_startup != 'Automatic':
			print('Service: %s is disabled.' % req_service)
		elif not service_status and service_startup == 'Automatic':
			formResult(color_wrap("[FAIL]", 'fail'), "Service: %s is not started! It is required for this test to run." % req_service)
		else:
			formResult(color_wrap("[INFO]", 'info'), "VCHA is not enabled.")
	else:
		print("Not applicable on this node.")

if __name__ == '__main__':
	if len(sys.argv) > 2:
		main_wrap(sys.argv[1], sys.argv[2])
	else:
		username,password = prompt()
		main_wrap(username,password)