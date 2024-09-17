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
__title__ = "VC AD CHECK"
import os
import atexit
import argparse
import ast
import getpass
import sys
import ssl
import time
import subprocess
from datetime import datetime, timedelta
import re
import socket
import vc_ports
import threading
parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
libdir = os.path.join(parentdir, 'lib')
sys.path.append(os.path.abspath(libdir))
from utils import getSingleServiceStatus, getStartup, Command
from pformatting import *
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vdt import setupLogging
import logging
import shlex
logger = logging.getLogger(__name__)
command_timeout = 5
# import vc_ports
# parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
# libdir = os.path.abspath(os.path.join(parentdir, 'lib'))
# sys.path.append(libdir)
# from utils import get_params, exec_batch

_DefaultCommmandEncoding = sys.getfilesystemencoding()
def run_command(cmd, stdin=None, quiet=False, close_fds=False,
				encoding=_DefaultCommmandEncoding, log_command=True):
	
	
	process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
							stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	timer = threading.Timer(10, process.kill)
	try:
		timer.start()
		if sys.version_info[0] >= 3 and isinstance(stdin, str):
			stdin = stdin.encode(encoding)
		stdout, stderr = process.communicate(stdin)
	finally:
		script = cmd[0]
		timer.cancel()
	return stdout

def getHostname():
	cmd = ['/usr/bin/hostname', '-f']
	output, errors, timeout = Command(cmd).run().strip()
	return output

def getAdDomain():
	cmd = ['/opt/likewise/bin/domainjoin-cli', 'query']
	query, errors, timeout = Command(cmd).run()
	query_result = query.split('\n')[1].split(' = ')
	if len(query_result) > 1:
		result = (query_result[1])
	else:
		result = ""
	return result

def FQDN_check():
	print(color_wrap("FQDN Check\n",'subheading'))
	domain = getAdDomain().lower()
	hostname = getHostname().lower()
	# hostname = 'brm-prod-vc.subdomain.brmstorage.com'
	if domain != "":
		if domain != hostname.split('.', 1)[1]:
			formResult(color_wrap("\t[FAIL]", 'fail'), "FQDN does not match domain membership!")
			print("\tDomain Name: %s\n\tHostname: %s" % (domain,hostname))
		else:
			formResult(color_wrap("\t[PASS]", 'pass'), "FQDN matches domain membership")
	else:
		formResult(color_wrap("\t[PASS]", 'pass'), "%s is not joined to a domain." % hostname)

def getDomains():
	results = []
	cmd = ['/opt/likewise/bin/lw-get-status']
	query, errors, timeout = Command(cmd).run()
	query_result = query.strip()
	for line in query_result.splitlines():
		line = line.strip()
		if line.startswith('DNS Domain'):
			results.append(line.split(':')[1].strip())
	return results

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

def getDcList(domain):

	domain = "\"" + domain + "\""
	results = []

	cmd = "\"/opt/likewise/bin/lw-get-dc-list " + domain + "\""
	query, errors, timeout = Command(cmd, shell=True).run()

	for line in query.splitlines():
		if line.startswith('DC '):
			line = line.split(': ', 1)[1].strip()
			line = line.split(',')
			entry = dict(x.split('=',1) for x in line)
			result = {k.strip():v.replace('\'','').strip() for k, v in entry.items()}
			results.append(result)
	return results

def dnsCheck(hostname):
	dnsmismatchkb = "https://kb.vmware.com/s/article/52930"
	failflag = False
	result = color_wrap("[PASS]",'pass')
	msg = "Forward and reverse DNS lookup for %s" % hostname
	alarm = []

	ip, hnresult = dns_lookup(hostname)
	
	
	if 'FAIL' in hnresult:
		failflag = True
		msg = "%s: Forward DNS lookup failed!" % hostname
		alarm.append("Forward Lookup: %s failed to resolve." % hostname)
	else:
		rhostname, ipresult = dns_lookup(ip)
		if 'FAIL' in ipresult:
			failflag = True
			msg = "%s: Reverse DNS lookup failed!" % hostname
			if rhostname == "":
				alarm.append("\t\t\tReverse Lookup: %s failed to resolve." % ip)

		if rhostname.lower() != hostname.lower() and rhostname != "":
			failflag = True
			msg = "%s: DNS lookup mismatch!" % hostname
			alarm.append("\t\t\t%s resolved to IP: %s\n\t\t\t%s resolved to %s\n\t\t\tSee %s" % (hostname,ip,ip,rhostname,dnsmismatchkb))
	if failflag:
		result = color_wrap("[FAIL]",'fail')
		formResult("\t" + result, msg)
		print("\t\tDetails:\n" + "\n\t".join(alarm))
		print()
	else:
		formResult("\t" + result, msg)

def portCheck(dc, ports):
	vc_ports.CheckConnect(dc, ports).check()

def report(override=False):
	ports = [88, 135, 389, 445, 464, 636, 3268, 3269]
	print(color_wrap("\nDomain Report:",'subheading'))
	
	results = {}
	domainlist = getDomains()
	if len(domainlist) > 0:
		if len(domainlist) >= 5 and override == False:
			msg = """
There are more than 5 domains.  Results could take a long time to complete.
If you would still like to run this test and wait for the output, simply
run 'python scripts/vc_ad_check.py --override'
			"""
			print(msg)
		else:
			print("  Checking ports: %s" % ', '.join([str(x) for x in ports]))
			for domain in domainlist:
				results[domain] = getDcList(domain)

			for domain in results:
				print("\n  Domain: %s\n" % domain)
				for dc in results[domain]:
					portCheck(dc['Name'], ports)
					dnsCheck(dc['Name'])
	else:
		print("\tNo domain(s) detected")

def getRegValue(regtree, regkey):
	result = []
	cmd = ["/opt/likewise/bin/lwregshell", "list_values", regtree]
	query, errors, timeout = Command(cmd).run()
	entries = '%s.+?(?=^...")' % regkey
	sortme = re.compile(entries,re.DOTALL|re.MULTILINE)
	out = sortme.findall(query)
	if len(out) > 0:
		temp_result = out[0].split()
		regkey_remove = [x.replace('"','') for x in temp_result if 'REG' not in x]
		result = [entry for entry in regkey_remove if regkey not in entry]
		result = [entry for entry in result if entry != '']
	
	return result

def getExcludeTrust():
	print(color_wrap("\nDomain Exclusion List:\n", 'subheading'))
	domain_list = getRegValue("[HKEY_THIS_MACHINE\Services\lsass\Parameters\Providers\ActiveDirectory]","DomainManagerExcludeTrustsList")
	if len(domain_list) >= 1:
		for item in domain_list:
			print('\t' + item)
	else:
		print('\t None')
	# print(trustExcludeList)

def getExcludedDcs():
	print(color_wrap("\nDC Exclusion List:\n", 'subheading'))
	dc_list = getRegValue("[HKEY_THIS_MACHINE\Services\\netlogon\Parameters]","BlacklistedDCs")
	if len(dc_list) >= 1:
		for item in dc_list:
			print('\t' + item)
	else:
		print('\t None')
def parse_argument():
    parser = argparse.ArgumentParser(description='VC AD Check',
                                 formatter_class=
                                 LineWrapRawTextHelpFormatter)

    parser.add_argument("-o", "--override",
                            action='store_true',
                            help="Print report on problems in the "
                                 "SSO domain")
    return parser


def main():
	if 'VDT-FORCE' in os.environ:
		if os.environ['VDT-FORCE'] == "TRUE":
			override = True
		else:
			override = False
		report(override)
	else:
	# FQDN_check()
		parser = parse_argument()
		args = parser.parse_args()
		report(args.override)
		getExcludeTrust()
		getExcludedDcs()

class LineWrapRawTextHelpFormatter(argparse.RawDescriptionHelpFormatter):
    
    def _split_lines(self, text, width):

        text = self._whitespace_matcher.sub(' ', text).strip()
        return _textwrap.wrap(text, width)

if __name__ == '__main__':
	setupLogging()
	# print(color_wrap("AD Check", 'title'))
	req_service = 'lwsmd'
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
