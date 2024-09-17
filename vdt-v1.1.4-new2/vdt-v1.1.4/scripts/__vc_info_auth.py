# -*- coding: utf-8 -*-
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
__title__ = "VCENTER BASIC INFO"
import os
import atexit
import argparse
import ast
import getpass
import sys
import ssl
import time
import subprocess
import re
from codecs import encode, decode
import xml.etree.ElementTree as xml
from datetime import datetime, timedelta
parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
libdir = os.path.abspath(os.path.join(parentdir, 'lib'))
sys.path.append(libdir)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import get_params, prompt
from pformatting import *
from multiprocessing import cpu_count
from vdt import setupLogging
import logging
try:
    from urllib.parse import urlparse as urlparse
except ImportError:
    from urlparse import urlparse as urlparse
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

def getDisabledPlugins():
	results = []
	matrix = xml.parse("/etc/vmware/vsphere-ui/compatibility-matrix.xml")
	plugins = matrix.findall('.//PluginPackage')
	for plugin in plugins:
		results.append(plugin.get('id'))
	if len(results) > 0:
		output = "\n\t" + '\n\t'.join(results)
	else:
		output = "None"		
	return output

def getHostname():
	logger.debug("Getting hostname")
	cmd = ['/usr/bin/hostname', '-f']
	return run_command(cmd).decode().strip()

def psqlQuery(query):
	logger.debug("running SQL query: %s" % query)
	psqlpath = "/opt/vmware/vpostgres/current/bin/psql"
	cmd = [psqlpath, '-d','VCDB', 'postgres', '-c', query]
	try:
		output = run_command(cmd)
		output = output.decode()
		output = output.split('\n')[2]
		return output.strip()
	except:
		msg = color_wrap("Requires vPostgres service!", 'fail')
		return msg

def getIp():
	logger.debug("Getting IP from ifconfig")
	ip = ""
	ifconfig = run_command(["ifconfig", "eth0"])
	ifconfig = ifconfig.decode()
	for line in ifconfig.split('\n'):
		mylist = list(line.split())
		for param in mylist:
			if "addr:" in param:
				ip = param.split(':')[1]
	return ip

def getNtpServers():
	logger.debug("Getting NTP servers from ntp.conf")
	ntpservers = []
	with open('/etc/ntp.conf') as ntpconf:
		data = ntpconf.read()
	for line in data.split('\n'):
		if 'server' in line:
			ntpservers.append(line.split()[1])
	result = ', '.join(ntpservers)
	return result

def getAdDomain():
	logger.debug("Getting AD domain from domainjoin-cli query")
	cmd = ['/opt/likewise/bin/domainjoin-cli', 'query']
	query = run_command(cmd).decode()
	query_result = query.split('\n')[1].split(' = ')
	if len(query_result) > 1:
		result = (query_result[1])
	else:
		result = "No DOMAIN"
	return result

def getMem():
	logger.debug("Getting memory")
	mem_bytes = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')  # e.g. 4015976448
	mem_gb = round(mem_bytes/(1024.**3), 2)
	return mem_gb

def getUptime():
	logger.debug("Getting uptime")
	cmd = ['/usr/bin/uptime']
	output = run_command(cmd).decode().split('\n')
	output = [x for x in output if x]
	output = output[0].split(',  ')
	uptime = output[0].split(', ')[0]
	uptime = uptime.split()
	del uptime[0]
	uptime = ' '.join(uptime)
	for item in output:
		if 'load average' in item:
			loadavg = item.replace('load average: ','')
		else:
			continue
	return uptime,loadavg

def getVchaConfig():
	# place holder
	pass

def getProxy():
	logger.debug("Getting proxy config")
	result = ""
	with open('/etc/sysconfig/proxy') as f:
		contents = f.read()
	for line in contents.splitlines():
		if 'PROXY_ENABLED' in line:
			result = line.split('=')[1]
	return result

def VcInfo():
	info = {}
	try:
		params = get_params().get()
		info["pnid"] = params['pnid']
		info["nodetype"] = params['deploytype']
		info["ssodomain"] = params['domain_name']
		info["version"] = params['version'] + " - " + params['build']
		info['PSC'] = urlparse(params['lsurl']).hostname
	except:
		print("Failed to get info from vmdir.  Please ensure vmafdd and vmdir are started.")
		info["ssodomain"] = color_wrap("Requires vmdir service!", 'fail')
		info["pnid"] = color_wrap("Requires vmdir service!", 'fail')
		info["nodetype"] = color_wrap("Requires vmdir service!", 'fail')
		info["version"] = color_wrap("Requires vmdir service!", 'fail')
	if info['nodetype'] == 'infrastructure':
		info['friendlytype'] = "External PSC"
	elif info['nodetype'] == 'management':
		info['friendlytype'] = "vCenter with External PSC"	
	elif info['nodetype'] == 'embedded':
		info['friendlytype'] = "vCenter with Embedded PSC"
	else:
		info['friendlytype'] = info['nodetype']
	uptime,loadavg = getUptime()
	info['proxy'] = getProxy()
	info['currenttime'] = datetime.now()
	info["hostname"] = getHostname()
	info["ip"] = getIp()
	info["addomain"] = getAdDomain()

	info["numcpus"] = cpu_count()
	info["nummem"] = getMem()
	if info['nodetype'] != "infrastructure":
		info["numhosts"] = psqlQuery("SELECT COUNT(*) FROM vpx_host;")
		info["numvms"] = psqlQuery("SELECT COUNT(*) FROM vpx_vm;")
		info["numclusters"] = psqlQuery("SELECT COUNT(*) FROM vpx_compute_resource WHERE resource_type=2;")
		info["disabledplugins"] = getDisabledPlugins()
	info["ntpservers"] = getNtpServers()
	info["uptime"] = uptime
	info["loadavg"] = loadavg
	
	return info

def main(username="", password=""):
	# print(color_wrap("VCENTER BASIC INFO", "title"))
	info = VcInfo()
	pnidkb = ""


	report = """
BASIC:
	Current Time: {currenttime}
	vCenter Uptime: {uptime}
	vCenter Load Average: {loadavg}
	Number of CPUs: {numcpus}
	Total Memory: {nummem}
	vCenter Hostname: {hostname}
	vCenter PNID: {pnid}
	vCenter IP Address: {ip}
	Proxy Configured: {proxy}
	NTP Servers: {ntpservers}
	vCenter Node Type: {friendlytype}
	vCenter Version: {version}
DETAILS:
	vCenter SSO Domain: {ssodomain}
	vCenter AD Domain: {addomain}""".format(**info)

	if info['nodetype'] == "management":
		report = report + """
	External PSC: {PSC}"""
	
	if info['nodetype'] != "infrastructure":
		report = report + """
	Number of ESXi Hosts: {numhosts}
	Number of Virtual Machines: {numvms}
	Number of Clusters: {numclusters}
	Disabled Plugins: {disabledplugins}"""
		
	report = report.format(**info)
	try:
		print(report)
	except:
		print(unicode(report))

	if info['pnid'] != info['hostname']:
		if info['pnid'].lower() == info['hostname'].lower():
			pnidkb = "https://kb.vmware.com/s/article/84355"
		else:
			pnidkb = "https://kb.vmware.com/s/article/2130599"
		formResult(color_wrap('\n[FAIL]', 'fail'), "The hostname and PNID do not match!\n" \
					"\tPlease see %s for more details." % pnidkb)

def main_wrap(username="", password=""):
	setupLogging()
	main(username,password)

if __name__ == '__main__':
	if len(sys.argv) > 2:
		main_wrap(sys.argv[1], sys.argv[2])
	else:
		username,password = prompt()
		main_wrap(username,password)