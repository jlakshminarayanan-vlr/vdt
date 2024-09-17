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
__title__ = "vCenter Port Check"
import socket
import time
import json
import os
import requests
import sys
import socket
parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
libdir = os.path.join(parentdir, 'lib')
sys.path.append(os.path.abspath(libdir))
from utils import get_params
from pformatting import *
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vdt import setupLogging
import logging
logger = logging.getLogger(__name__)

ca_dir = '/etc/ssl/certs/'
testkb = "https://kb.vmware.com/s/article/52963"
hostname = socket.gethostname()

class GetTopology(object):
	def __init__(self, username, password):
		self.hostname = hostname

		session_url = 'https://%s:443/rest/com/vmware/cis/session' % self.hostname
		try:
			r = requests.post(url=session_url, auth=(username,password), verify='/etc/ssl/certs/', timeout=5)
		except:
			print("Failed to logon session!  Services down?")
			raise
		session = json.loads(r.text)
		self.api_token = {"vmware-api-session-id" : session['value']}

	def api_call(self, method, url):
		if method == 'post':
			r = requests.post(url=url, headers=self.api_token, verify='/etc/ssl/certs/', timeout=5)
		elif method == 'get':
			try:
				r = requests.get(url=url, headers=self.api_token, verify='/etc/ssl/certs/', timeout=5)
			except Exception as e:
				print(bcolors.FAIL + "ERROR: " + bcolors.ENDC + "Couldn't issue API call!  Is there a service stopped?")
				raise

		else:
			raise
		if r.text:
			response = json.loads(r.text)
		
		if response['value']:
			# msg = "Call successful for %s to %s:" % (method, url)
			result = response['value'][0]
		else:
			msg = "No result found for %s request to %s" % (method, url)
			print(msg)
			result = None
		
		return result

	def nodes(self):
		url = 'https://%s/rest/vcenter/topology/nodes' % self.hostname
		return self.api_call('get', url)

	def replication(self):
		url = 'https://%s/rest/vcenter/topology/replication-status' % self.hostname
		return self.api_call('get', url)

class CheckConnect(object):
	
	def __init__(self, ip, ports):
		#  Spec will be yaml parameters specific to the product
		self.retry = 1
		self.delay = 2
		self.timeout = 5
		self.ip = ip
		self.ports = ports
		self.ptype = "TCP"

		self.init_msg = "Port check for host %s" % self.ip

	def TCP(self, port):
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.settimeout(self.timeout)
			rc = 1
			try:
					response = s.connect((self.ip, int(port)))
					s.shutdown(socket.SHUT_RDWR)
					s.close()
					result = "tcp port test returned %s" % response
					logger.debug(result)
					rc = 0
			except Exception as e:
					result = "tcp port test failed. error was: %s" % e
					logger.debug(result)
			return rc, result

	def check(self):
		result = False
		failflag = False
		alarms = []
		for port in self.ports:
			port_msg = "Port " + str(port)
			for attempt in range(self.retry):
				rc, result = self.TCP(port)
				if rc == 0:
					result = True
					break
				else:
					time.sleep(self.delay)
			if result != True:
				alarms.append(color_wrap("\t[FAIL]",'fail') + "\t" + port_msg)
				failflag = True
		if failflag == True:
			formResult(color_wrap("\t[FAIL]",'fail'), self.init_msg)
			for alarm in alarms:
				print(alarm)
		else:
			formResult(color_wrap("\t[PASS]",'pass'), self.init_msg)

if __name__ == '__main__':
	#SOME DAY WE WILL CHECK REPLICATION PARTNERS TOO
	setupLogging()
	# print(color_wrap("vCenter Port Check",'title'))
	try:
		params = get_params().get()
		if params['deploytype'] == 'management':
			ports = [443, 2020]
		else:
			ports = [443, 389, 2012, 2020]
	except:
		print("Failed to get parameters from vmafd/vmdir.  Checking 443 anyway.")
		ports = [443]
		pass
	
	print("Checking ports: %s" % ', '.join([str(x) for x in ports]))
	print("For port information, please see KB: %s\n" % testkb)
	CheckConnect(hostname, ports).check()
