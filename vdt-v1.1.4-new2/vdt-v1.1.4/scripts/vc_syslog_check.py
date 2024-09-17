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
__title__ = "Syslog Check"
import os
import sys
import stat
import time
import re
import socket
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
libdir = os.path.join(parentdir, 'lib')
sys.path.append(os.path.abspath(libdir))
from utils import Command
from pformatting import *
from vdt import setupLogging
import logging
logger = logging.getLogger(__name__)


def getSyslog():
	logger.debug("Getting syslog config")
	file = "/etc/vmware-syslog/syslog.conf"
	pattern = "@(.*?);"
	server = "None configured"
	with open(file) as f:
		data = f.read()
	for line in data.splitlines():
		if '@' in line:
			line = line.replace("(o)", '')
			server = re.search(pattern,line).group(1)
	return server

def writeSyslog(message):
	tag = str(time.strftime("vdt" + "-%Y-%m-%d-%H%M%S"))
	logger.debug("Created tag %s to test syslog" % tag)
	cmd = ['/usr/bin/logger', message, '-t', tag]
	Command(cmd).run()
	return tag

def checkSyslogTest(file, tag, lines=100):
	kb_link = "https://kb.vmware.com/s/article/81829"
	failuremsg = """
\tThe syslog daemon is not writing to the logs it manages:
\t/var/log/vmware/messages, /var/log/vmdird/vmdird-syslog.log, etc.
\tPlease see %s\n
""" % kb_link
	result = False
	logger.debug("Searching %s for %s" % (file, tag))
	with open(file) as syslogfile:
		for line in (syslogfile.readlines() [-lines:]):
			if tag in line:
				logger.debug("Found string: %s" % tag)
				result = True
	if result:
		formResult(color_wrap('[PASS]','pass'), "Local Syslog Functional Check")
	else:
		logger.debug("Did not find string: %s in file %s" % (tag, file))
		formResult(color_wrap('[FAIL]','fail'), "Local Syslog Functional Check")
		print(failuremsg)
	return result

def validateIPorHost(address):
	is_ip = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", address)
	is_hostname = re.match("^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$", address)
	if is_ip:
		return 'IP'
	if is_hostname:
		return 'HOSTNAME'

def dns_lookup(addr):
	addr_type = validateIPorHost(addr)
	result = ""
	address = ""
	if addr_type == 'IP':
		try:
			address = socket.gethostbyaddr(addr)[0]
			result = color_wrap('[PASS]', 'pass')
			
		except:
			result = color_wrap("[FAIL]",'fail')
		# print("Reverse lookup for IP %s resolved to hostname %s" % (addr, hostname[0]))
	if addr_type == 'HOSTNAME':
		try:
			address = socket.gethostbyname(addr)
			result = color_wrap('[PASS]', 'pass') 
		except:
			result = color_wrap("[FAIL]",'fail')
	return address, result

def resolveSyslogServer(server):
	address, result = dns_lookup(server)
	if address == "":
		msg = "DNS lookup for %s could not be resolved." % server
	else:
		msg = "DNS lookup for %s resolved to %s" % (server, address)
	logger.debug(msg)
	return result, address

def main():

	syslogconfig = getSyslog()
	print("Remote Syslog config: %s\n" % syslogconfig)
	syslogfile = '/var/log/vmware/messages'
	tagsearch = writeSyslog("VDT SYSLOG TEST MESSAGE")
	if "None configured" not in syslogconfig:
		msg = """
	We've detected you have a remote syslog server configured.  
	Please search your remote syslog server for this string to 
	validate syslog is working correctly:

	%s
	""" % color_wrap(tagsearch,'info')
		server = syslogconfig.split(':')[0]
		server = server.replace("@","")
		result, address = resolveSyslogServer(server)
		formResult(result, "DNS lookup for %s" % server)
		print(msg)
		
	checkSyslogTest(syslogfile,tagsearch)

if __name__ == '__main__':
	setupLogging()
	# print(color_wrap("Syslog Check", 'title'))
	main()
