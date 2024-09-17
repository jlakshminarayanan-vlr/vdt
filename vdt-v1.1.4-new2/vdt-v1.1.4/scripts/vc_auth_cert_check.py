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
__title__ = "VC CERTIFICATE CHECK"
import socket
import re
import xml.etree.ElementTree as ET
import os
import sys
import json
import subprocess
import re
import pprint
import ssl
# import xml.etree.ElementTree as ET
from collections import OrderedDict
from datetime import datetime, timedelta
import textwrap
from codecs import encode, decode
from time import sleep
try:
	# Python 3 hack.
	import urllib.request as urllib2
	import urllib.parse as urlparse
except ImportError:
	import urllib2
	import urlparse

sys.path.append(os.environ['VMWARE_PYTHON_PATH'])
from pyVmomi.VmomiSupport import newestVersions
from pyVmomi import SoapStubAdapter, Vim
from cis.utils import FileBuffer
from cis.defaults import def_by_os, get_cis_install_dir, get_cis_config_dir

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
libdir = os.path.join(parentdir, 'lib')
sys.path.append(os.path.abspath(libdir))
from utils import VmafdClient, getSingleServiceStatus, getStartup, psqlQuery, getCert, Command, prompt
from pformatting import *

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vdt import setupLogging

from OpenSSL.crypto import (load_certificate, dump_privatekey, dump_certificate, X509, X509Name, PKey)
from OpenSSL.crypto import (TYPE_DSA, TYPE_RSA, FILETYPE_PEM, FILETYPE_ASN1 )

import logging
logger = logging.getLogger(__name__)

vcsa_kblink = "https://kb.vmware.com/s/article/76719"
win_kblink = "https://kb.vmware.com/s/article/79263"

today = datetime.now()
today = today.strftime("%d-%m-%Y")
delay = 1
timeout = 2

########### CONFIGURABLE PARAMETERS ###########
NUM_DAYS_CRITICAL = 30
NUM_DAYS_WARNING = 60
NUM_DAYS_INFO = 90
CHECKS = {"CRITICAL" : NUM_DAYS_CRITICAL,
		"WARNING": NUM_DAYS_WARNING, 
		"INFO": NUM_DAYS_INFO}

##### END IMPORTS #####

_DefaultCommmandEncoding = sys.getfilesystemencoding()
def get_rhttpProxy_config():
	'''
	Helper method to read config.xml to get rhttpProxy ports and
	its endpoints directory
	'''
	cisConfigDir = get_cis_config_dir()
	rhttpProxyConfigDir = def_by_os('%s-rhttpproxy' % cisConfigDir,
		os.path.join(cisConfigDir, 'vmware-rhttpproxy'))

	if not os.path.isdir(rhttpProxyConfigDir):
		sys.exit('\nERROR: "%s" is not a valid directory' % rhttpProxyConfigDir)
		sys.exit(-1)

	tree = ET.parse(os.path.join(rhttpProxyConfigDir, 'config.xml'))
	proxy = tree.getroot().find('proxy')
	httpPort = httpsPort = endpointsDir = None
	if proxy is not None:
		httpsPort = proxy.find('httpsPort').text
		httpPort  = proxy.find('httpPort').text
		endpointsDirectory  = proxy.find('endpointsDirectory').text

	httpsPort = int(httpsPort) if httpsPort and httpsPort.strip() else 443
	httpPort = int(httpPort) if httpPort and httpPort.strip() else 80
	endpointsDirectory = endpointsDirectory if endpointsDirectory and \
		endpointsDirectory.strip() else \
		os.path.join(rhttpProxyConfigDir, 'endpoints.conf.d')

	return (httpPort, httpsPort, endpointsDirectory)

def test_login(username, password):
    (httpPort, httpsPort, endpointsDir) = get_rhttpProxy_config()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    result = False

    try:
        stub = SoapStubAdapter(host='localhost', port=httpsPort, path='/sdk',
            version=newestVersions.GetName('vpx'), sslContext=context)
    except:
        stub = SoapStubAdapter(host='localhost', port=httpsPort, path='/sdk',
            version=newestVersions.Get('vpx'), sslContext=context)
    si = Vim.ServiceInstance('ServiceInstance', stub)
    sessionMgr = None
    try:
        sessionMgr = si.content.sessionManager
        sessionMgr.Login(username, password)
        sessionMgr is not None
        sessionMgr.Logout()
        result = True
    except Exception as e:
        # print('ERROR: Invalid user credentials. Please try again.')
        # print(e)
        pass
    return result

def run_command(cmd, stdin=None, quiet=False, close_fds=False,
				encoding=_DefaultCommmandEncoding, log_command=True):

	process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
							stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	if sys.version_info[0] >= 3 and isinstance(stdin, str):
		stdin = stdin.encode(encoding)
	stdout, stderr = process.communicate(stdin)
	if not stdout:
		print(color_wrap(stderr.decode(),'fail'))
		sys.exit(1)
	return stdout

def getNodeType():
	result = ""
	try:
		node_params['deploytype'] =  get_install_parameter('deployment.node.type', quiet=True)
	except:
		file = os.path.join(os.environ['VMWARE_CFG_DIR'],'deployment.node.type')
		with open(file) as fp:
			result = fp.read()
	result = "".join(result.split())
	return result

class parseCert( object ):
	"""
	This is a class that will parse a certificate into a dictionary of certificate information.
	
	Attributes:
		rawcert (TYPE): Description
		x509 (TYPE): Description
	"""
	def __init__(self, certdata, file=True):
		"""
		Args:
			certdata (TYPE): certificate data either string or file.
			file (bool, optional): flag telling us whether or not certdata is a file.
		"""
		if file == True:
			built_cert = certdata
			logger.debug(built_cert)
			logger.debug(type(built_cert))
			self.x509 = load_certificate(FILETYPE_PEM, built_cert)
		else:
			stringed_cert = re.sub("(.{64})", "\\1\n", certdata, 0, re.DOTALL)
			built_cert = "-----BEGIN CERTIFICATE-----\n" + stringed_cert +"\n" + "-----END CERTIFICATE-----"
			lines = '\n'.join([x for x in built_cert.split("\n") if x.strip()!=''])
			built_cert = lines
			self.x509 = load_certificate(FILETYPE_PEM, built_cert)
			self.rawcert = built_cert

	def decode(self, item, encoding):

		try:
			return decode(item, encoding, errors='surrogateescape' )
		except:
			return item.decode(encoding, errors='surrogateescape')

	def format_subject_issuer(self, x509name):

		items = []
		for item in x509name.get_components():
			items.append('%s=%s' %  (self.decode(item[0],'ascii'), self.decode(item[1],'ascii')))
		return ", ".join(items)

	def format_asn1_date(self, d):

		return datetime.strptime(self.decode(d,'ascii'), '%Y%m%d%H%M%SZ').strftime("%Y-%m-%d %H:%M:%S GMT")
  
	def merge_cert(self, extensions, certificate):

		z = certificate.copy()
		z.update(extensions)
		return z

	def cert(self):

		keytype = self.x509.get_pubkey().type()
		keytype_list = {TYPE_RSA:'rsaEncryption', TYPE_DSA:'dsaEncryption', 408:'id-ecPublicKey'}
		extension_list = ["extendedKeyUsage",
						"keyUsage",
						"subjectAltName",
						"subjectKeyIdentifier",
						"authorityKeyIdentifier"]

		key_type_str = keytype_list[keytype] if keytype in keytype_list else 'other'

		certificate = {}
		extension = {}
		for i in range(self.x509.get_extension_count()):
			critical = 'critical' if self.x509.get_extension(i).get_critical() else ''
		  
			if self.decode(self.x509.get_extension(i).get_short_name(),'ascii') in extension_list:
				try:
					extension[self.decode(self.x509.get_extension(i).get_short_name(),'ascii')] = self.x509.get_extension(i).__str__()
				except Exception as e:
					name = self.x509.get_extension(i).get_short_name()
					extension[self.decode(name,'ascii')] = "FAILED_TO_DECODE"
					logger.debug("Failed to parse certificate extension %s" % name)
					
		certificate = {'Thumbprint': self.decode(self.x509.digest('sha1'),'ascii'), 
					'Version': self.x509.get_version(),
					'SignatureAlg' : self.decode(self.x509.get_signature_algorithm(),'ascii'), 
					'Issuer' :self.format_subject_issuer(self.x509.get_issuer()), 
					'Valid From' : self.format_asn1_date(self.x509.get_notBefore()), 
					'Valid Until' : self.format_asn1_date(self.x509.get_notAfter()),
					'Subject' : self.format_subject_issuer(self.x509.get_subject())}
		combined = self.merge_cert(extension,certificate)

		cert_output = json.dumps(combined)
		# print(cert_output)
		# sys.exit()
		return cert_output
  
	def __str__(self):
		"""
		returns the certificate in string form if desired.
		"""
		return self.cert()

class Cert(object):
	def __init__(self, cert):
		combined = json.loads(str(parseCert(cert)))
		self.subjectAltName = combined.get('subjectAltName')
		self.subject = combined.get('Subject')
		self.validfrom = combined.get('Valid From')
		self.validuntil = combined.get('Valid Until')
		self.thumbprint = combined.get('Thumbprint')
		self.subjectkey = combined.get('subjectKeyIdentifier')
		self.authkey = combined.get('authorityKeyIdentifier')
		self.sigalg = combined.get('SignatureAlg')
		self.keyusage = combined.get('keyUsage')
		self.extkeyusage = combined.get('extendedKeyUsage')
		self.combined = combined

class parseSts( object ):

	def __init__(self):
		self.processed = []
		self.results = {}
		self.results['expired'] = {}
		self.results['expired']['root'] = []
		self.results['expired']['leaf'] = []
		self.results['valid'] = {}
		self.results['valid']['root'] = []
		self.results['valid']['leaf'] = []

	def get_certs(self,force_refresh):
		logger.debug("getting STS certs")
		urllib2.getproxies = lambda: {}
		vmafd_client = VmafdClient()
		domain_name = vmafd_client.get_domain_name()
		dc_name = urlparse.urlparse(vmafd_client.get_ls_location()).hostname
		vmafd_pnid = vmafd_client.get_pnid()
		if vmafd_pnid == dc_name:
			url = (
				'http://localhost:7080/idm/tenant/%s/certificates?scope=TENANT'
				% domain_name)
		else:
			url = (
				'https://%s/idm/tenant/%s/certificates?scope=TENANT'
				% (dc_name,domain_name))
		try:
			result = json.loads(urllib2.urlopen(url).read().decode('utf-8'))
		except Exception as e:
			e = str(e.reason).split(']')[1]
			raise Exception(e)
		return result

	def check_cert(self,certificate):
		logger.debug("Checking certificate: %s" % certificate)
		cert = Cert(certificate)
		certdetail = cert.combined

			#  Attempt to identify what type of certificate it is
		if cert.authkey:
			cert_type = "leaf"
		else:
			cert_type = "root"
		
		#  Try to only process a cert once
		if cert.thumbprint not in self.processed:
			# Date conversion
			self.processed.append(cert.thumbprint)
			exp = cert.validuntil.split()[0]
			conv_exp = datetime.strptime(exp, '%Y-%m-%d')
			exp = datetime.strftime(conv_exp, '%d-%m-%Y')
			now = datetime.strptime(today, '%d-%m-%Y')
			exp_date = datetime.strptime(exp, '%d-%m-%Y')
			
			# Get number of days until it expires
			diff = exp_date - now
			certdetail['daysUntil'] = diff.days

			# Sort expired certs into leafs and roots, put the rest in goodcerts.
			if exp_date <= now:
				self.results['expired'][cert_type].append(certdetail)
			else:
				self.results['valid'][cert_type].append(certdetail)
	
	def execute(self):

		json = self.get_certs(force_refresh=False)
		for item in json:
			for certificate in item['certificates']:
				self.check_cert(certificate['encoded'])
		return self.results

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
	if addr_type == 'IP':
		try:
			address = socket.gethostbyaddr(addr)[0]
			result = bcolors.OKGREEN + "[PASS]" + bcolors.ENDC   
		except:
			result = bcolors.FAIL+ "[FAIL]" + bcolors.ENDC   
		# print("Reverse lookup for IP %s resolved to hostname %s" % (addr, hostname[0]))
	if addr_type == 'HOSTNAME':
		try:
			address = socket.gethostbyname(addr)
			result = bcolors.OKGREEN + "\t[PASS]" + bcolors.ENDC   
		except:
			result = bcolors.FAIL+ "\t[FAIL]" + bcolors.ENDC
	return address, result

class checkCert( object ):

	def __init__(self, certdata, hostname="", ip="", alias="", note=""):
		self.load_cert = Cert(certdata)
		self.sigalg = self.load_cert.sigalg
		self.alias = alias
		self.note = note
		self.subject = self.load_cert.subject
		logger.debug("Checking certificate: %s for problems" % self.subject)
		if self.load_cert.authkey:
			if self.load_cert.authkey != "FAILED_TO_DECODE":
				self.authkey = self.load_cert.authkey.replace('keyid:','')
				self.authkey = self.authkey.strip()
			else:
				self.authkey = "ERROR!"
		else:
			self.authkey = None
		self.exp = self.load_cert.validuntil.split()[0]
		self.cert_name = self.load_cert.thumbprint
		self.subjectkey = self.load_cert.subjectkey
		self.exp_certs = {}
		self.hostname = hostname
		self.ip = ip
		self.certlist = trusted_list
		self.trustchain = {}
		sol_users = ['vpxd-extension','vpxd','machine','wcp','vsphere-webclient','hvc']

	def expCheck(self):
		logger.debug("Checking cert expiration")
		error = ""
		if self.alias == "vmdir":
			help_msg = """
	For information on renewing the vmdir certificate, see:
	https://docs.vmware.com/en/VMware-vSphere/6.0/com.vmware.vsphere.security.doc/GUID-585CF428-2BBC-47CE-A386-9A39D3DFE0BF.html
		"""
		else:
			help_msg = """
	For information on renewing certificates, see:  https://kb.vmware.com/s/article/68171
		"""

		conv_exp = datetime.strptime(self.exp, '%Y-%m-%d')
		exp = datetime.strftime(conv_exp, '%d-%m-%Y')
		exp_date = datetime.strptime(exp, '%d-%m-%Y')
		now = datetime.strptime(today, '%d-%m-%Y')
		if exp_date <= now + timedelta(days=CHECKS.get("CRITICAL")):
			result = bcolors.FAIL + "\t[FAIL]" + bcolors.ENDC
			diff = exp_date - now
			exp_in_days = diff.days
			if exp_in_days < 0:
				negative_days = str(exp_in_days).replace('-','')
				error = "\t\t%s: Cert expired %s days ago!  %s" % (self.cert_name, negative_days, help_msg)
			else:
				error = "\t\t%s: Cert will expire in %s days!  %s" % (self.cert_name, exp_in_days, help_msg)

		elif exp_date <= now + timedelta(days=CHECKS.get("WARNING")):
			result = bcolors.WARNING + "\t[WARNING]" + bcolors.ENDC
			diff = exp_date - now
			exp_in_days = diff.days
			error = "\t\t%s: Cert will expire in %s days!  %s" % (self.cert_name, exp_in_days, help_msg)

		elif exp_date <= now + timedelta(days=CHECKS.get("INFO")):
			result = bcolors.OKCYAN + "\t[INFO]" + bcolors.ENDC
			diff = exp_date - now
			exp_in_days = diff.days
			error = "\t\t%s: Cert will expire in %s days!  %s" % (self.cert_name, exp_in_days, help_msg)
		else:
			result = bcolors.OKGREEN + "\t[PASS]" + bcolors.ENDC
		
		msg = "Certificate expiration check"
		formResult(result,msg)
		
		if error != "":
			print(error)

	def sanCheck(self):
		logger.debug("Checking SAN")
		self.san = self.load_cert.subjectAltName
		error = ""
		hostflag = True
		ipflag = True
		
		if self.san:
			if self.hostname.lower() not in self.san.lower():
				hostflag = False
				result = bcolors.FAIL + "\t[FAIL]" + bcolors.ENDC
				error = "%s: Hostname is not in the SAN!" % self.cert_name
				if self.ip not in self.san:
					ipflag = False
					error = "Neither hostname nor IP in the SAN!"
			if self.ip != "":
				if self.ip not in self.san:
					ipflag = False
					result = bcolors.OKGREEN + "\t[PASS]" + bcolors.ENDC
			
			if hostflag == True and ipflag == True:
				result = bcolors.OKGREEN + "\t[PASS]" + bcolors.ENDC
			if hostflag == True and ipflag == False:
				result = bcolors.WARNING + "\t[INFO]" + bcolors.ENDC
				error = "\tDETAILS: SAN contains hostname but not IP."
			if hostflag == False and ipflag == True:
				result = bcolors.WARNING + "\t[WARN]" + bcolors.ENDC
				error = "\tDETAILS: SAN contains IP but not hostname.  This configuration is not recommended."
			if hostflag == False and ipflag == False:
				result = bcolors.FAIL + "\t[FAIL]" + bcolors.ENDC
				error = "\tDETAILS: %s - SAN contains neither hostname nor IP!" % self.cert_name
		else:
			result = color_wrap('\t[WARN]','warn')
			error = "\tDETAILS: No SAN detected"

		msg = "Certificate SAN check"
		formResult(result,msg)
		if error != "":
			print(error)

	def algCheck(self):
		logger.debug("Checking Sig Algorithm")
		msg = "Supported Signature Algorithm"
		error = ""
		if "sha1" in self.sigalg:
			result = color_wrap("\t[FAIL]",'fail')
			error = """
%s is not a supported algorithm.  Please see the document 'Certificate Requirements for Different Solution Paths'
on https://docs.vmware.com corresponding to your version.
""" % self.sigalg
		else:
			result = color_wrap("\t[PASS]",'pass')
		formResult(result,msg)
		if error != "":
			print(error)
	
	def getTrustChain(self, authkey, canum=0):
		rc = 1
		cacount = 'ca' + str(canum)
		if authkey != None:
			for cert in self.certlist:
				if authkey == self.certlist[cert]['subjectkey']:
					canum += 1
					rc = 0
					self.trustchain[cacount] = cert
					if not 'children' in trusted_list[cert].keys():
						trusted_list[cert]['children'] = []
					
					if self.alias == "":
						self.alias = self.cert_name
					
					if self.note != "":
						self.alias = self.alias + " (" + self.note + ")"

					trusted_list[cert]['children'].append(self.alias)
					if self.certlist[cert]['authkey'] != self.certlist[cert]['subjectkey']:
						self.getTrustChain(self.certlist[cert]['authkey'], canum)
				else:
					continue
		else:
			rc = 0
		
		if rc == 1:
			self.trustchain[authkey] = "Signing authority does not exist in TRUSTED_ROOTS!"
	
	def printChain(self):
		trustchain = OrderedDict(sorted(self.trustchain.items()))
		for ca, alias in trustchain.items():
			print("\t  See TRUSTED_ROOTS alias: %s" % alias)

	def trustCheck(self):
		# print(self.certlist)
		logger.debug("Checking if certificate is trusted")
		error = ""
		result = ""
		msg = "Certificate trust check"
		if self.authkey:
			# print(self.authkey)\
			if self.authkey == "ERROR!":
				result = color_wrap("\t[WARN]",'warn')
				error = "\tDETAILS:  Certicate has an empty Authority Key Identifier.  This is no longer supported.  Please regenerate this certificate."
			
			elif self.subjectkey in self.authkey:
				result = bcolors.OKGREEN + "\t[PASS]" + bcolors.ENDC
				msg = "Certificate is self-signed"
			
			else:
				self.getTrustChain(self.authkey)
				rc = 1
				logger.debug("Checking authkey: %s" % self.authkey)
				for cert in self.certlist:
					if self.certlist[cert]['subjectkey']:

						logger.debug("compare %s with %s" % (self.authkey, self.certlist[cert]['subjectkey']))
						
						if self.authkey in self.certlist[cert]['subjectkey']:
							logger.debug("MATCHED")
							result = bcolors.OKGREEN + "\t[PASS]" + bcolors.ENDC
							rc = 0
						else:
							
							logger.debug("NOT MATCHED")
							continue

				if rc:
					result = bcolors.FAIL + "\t[FAIL]" + bcolors.ENDC
					error = "\tDETAILS: Signing authority does not exist in TRUSTED_ROOTS!"
					logger.debug(self.authkey)
		else:
			result = bcolors.OKGREEN + "\t[PASS]" + bcolors.ENDC
			msg = "Certificate is self-signed"
		formResult(result,msg)

		if error != "":
			print(error)

	def caCheck(self):
		logger.debug("Checking if certificate is a CA")
		keyusage = self.load_cert.keyusage
		if keyusage:
			if 'Certificate Sign' in keyusage:
				return True
			else:
				return False
		else:
			return False

	def extKeyUsageCheck(self):
		msg = "Check extended key usage"
		result = ""
		result = color_wrap("\t[PASS]",'pass')
		extKeyUsage = self.load_cert.extkeyusage
		err = ""
		if extKeyUsage:
			if 'TLS Web Client Authentication' not in extKeyUsage:
				result = color_wrap("\t[FAIL]",'fail')
				err = "\tvpxd-extension solution user must have 'TLS Web Client Authentication'!"
		formResult(result,msg)
		if err != "":
			print(err)

	
	def execute(self,alg=True,exp=True,san=True,ca=False,trust=True,extusage=False):
		
		self.printChain()
		if alg:
			self.algCheck()
		if trust:
			self.trustCheck()
		if exp:
			self.expCheck()
		if extusage:
			self.extKeyUsageCheck()
		if san:
			self.sanCheck()
		if ca:
			self.caCheck()
			# print(trusted_list.keys())
			# print(self.cert_name)
			for entry in trusted_list:
				if self.alias in trusted_list[entry]:
					if 'children' in trusted_list[self.alias].keys():
						print("\t  Child certificates:")
						for child in trusted_list[self.alias]['children']:
							print("\t\t%s" % child)
	

def getAddr():
	logger.debug("getting IP and resolving to hostname")
	ip = ""
	ifconfig = run_command(["ifconfig", "eth0"])
	ifconfig = ifconfig.decode()
	for line in ifconfig.split('\n'):
		mylist = list(line.split())
		for param in mylist:
			# print("-----------------")
			# print(param)
			if "addr:" in param:
				# print(param)
				ip = param.split(':')[1]
	hostname = socket.gethostname()
	logger.debug("IP: %s, Hostname: %s" % (ip, hostname))
	return ip, hostname

def dnsCheck():

	print(color_wrap("DNS Check",'subheading'))

	myip,myhostname = getAddr()
	print('IP found for eth0: [%s]' % myip)
	
	myhn, result = dns_lookup(myip)
	msg = "nslookup %s" % myip
	formResult(result, msg)

	mycheck, result = dns_lookup(myhostname)
	msg = "nslookup %s" % myhostname
	formResult(result,msg)

class GetVecs(object):
	def __init__(self, ignore_list=None):
		self.vecscli = "/usr/lib/vmware-vmafd/bin/vecs-cli"
		self.ignore_list = ignore_list

	def GetVecsStores(self):
		output = []
		# logger.debug("Getting certificate with Alias: %s from Store: %s" % (alias,store))

		raw, errors, timeout = Command([self.vecscli, "store", "list"]).run()
		for store in raw.splitlines():
			if store not in self.ignore_list:
				output.append(store)
		return output

	def ListStoreCerts(self, store):
		output = []
		raw, errors, timeout = Command([self.vecscli, "entry", "list", "--store", store]).run()
		for line in raw.splitlines():
			if 'Alias' in line:
				output.append(line.split(":", 1)[1].strip())
		return output

	def GetVecsCert(self, store, alias):
		logger.debug("Getting certificate with Alias: %s from Store: %s" % (alias,store))
		cert, errors, timeout = Command([self.vecscli, "entry", "getcert", "--store", store, "--alias", alias]).run()
		return cert

	def all(self):
		output = {}
		for store in self.GetVecsStores():
			output[store] = {}
			for alias in self.ListStoreCerts(store):
				output[store][alias] = self.GetVecsCert(store, alias)
		return output

class exManager(object):
	def __init__(self, username, password):
		(httpPort, httpsPort, endpointsDir) = get_rhttpProxy_config()
		context = ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE

		try:
			stub = SoapStubAdapter(host='localhost', port=httpsPort, path='/sdk',
				version=newestVersions.GetName('vpx'), sslContext=context)
		except:
			stub = SoapStubAdapter(host='localhost', port=httpsPort, path='/sdk',
				version=newestVersions.Get('vpx'), sslContext=context)
		si = Vim.ServiceInstance('ServiceInstance', stub)

		self.sessionMgr = None
		try:
			self.sessionMgr = si.content.sessionManager
			self.sessionMgr.Login(username, password)
		except Vim.fault.InvalidLogin:
			# print('ERROR: Invalid user credentials. Please try again.')
			raise Exception("Invalid user credentials")
		self.em = si.content.extensionManager
		self.settings = si.content.setting.setting
	
	def getSetting(self, setting_key):
		for setting in self.settings:
			if setting.key == setting_key:
				return setting.value

	def getExtThumbprint(self, ext_name):
		output = psqlQuery('SELECT thumbprint from vpx_ext where ext_id=\'%s\'' % ext_name)
		return output
	
	def list(self):
		results = {}
		try:
			for extension in self.em.extensionList:
				ex_key = extension.GetKey()
				# print(extension)
				results[ex_key] = {}
				results[ex_key]['label'] = extension.description.label
				results[ex_key]['description'] = extension.description.summary
				results[ex_key]['company'] = extension.company
				results[ex_key]['version'] = extension.version
				dbtp = self.getExtThumbprint(ex_key)
				try:
					results[ex_key]['hostname'] = urlparse.urlparse(extension.server[0].url).hostname
					if dbtp == "":
						results[ex_key]['thumbprint'] = extension.server[0].serverThumbprint
					else:
						results[ex_key]['thumbprint'] = dbtp
				except:
					results[ex_key]['thumbprint'] = dbtp
			return results
		finally:
			assert self.sessionMgr is not None
			self.sessionMgr.Logout()
			self.sessionMgr = None
	
	def findByExtName(self, ex_name):
		extensions = self.list()
		results = {}
		for extension in extensions:
			if ex_name in extension:
				results[extension] = extensions[extension]
		return results

def checkExtCerts(username, password):
	logger.debug("Checking extension registrations.")
	print(color_wrap('\tChecking VC Extension Thumbprints', 'subheading'))
	extensions = ['com.vmware.vim.eam','com.vmware.rbd', 'com.vmware.imagebuilder']
	VecsClient = GetVecs()
	cert = getCert(VecsClient.GetVecsCert('vpxd-extension','vpxd-extension'))
	vpxd_ext_thumb = cert.thumbprint
	logger.debug("Got vpxd-extension solution user thumbprint: %s" % vpxd_ext_thumb)
	try:
		client = exManager(username,password)
		extension_list = client.list()
		for extension in extensions:
			errors = []
			extmsg = "%s Thumbprint Check" % extension
			if extension in extension_list.keys():
				ext_thumb = extension_list[extension]['thumbprint']
				logger.debug("Got vpxd-extension solution user thumbprint: %s" % vpxd_ext_thumb)
				if ext_thumb == vpxd_ext_thumb:
					result = color_wrap("\t\t[PASS]",'pass')
				else:
					errors.append("\t\t\tPROBLEM: Thumbprint mismatch detected with %s.\n\t\t\tPlease follow https://kb.vmware.com/s/article/57379 to update the thumbprint.\n" % extension)
					result = color_wrap("\t\t[FAIL]",'fail')
			else:
				formResult(color_wrap("\t\t[INFO]",'info'), extmsg)
				print("\t\t\t%s not found in registered extensions (not in use)." % extension)
				continue

			formResult(result, extmsg)
			if len(errors) > 0:
				for err in errors:
					print(err)
	except Exception as e:
		formResult(color_wrap("\t\t[WARN]",'warn'), "Cannot check extensions.  error was: %s" % str(e))

def getCaTrustList():
	logger.debug("Getting CA trust list")
	certlist = run_command(["/usr/lib/vmware-vmafd/bin/vecs-cli", "entry", "list", "--store", "TRUSTED_ROOTS"]).decode()
	templist = certlist.splitlines()
	templist[0] = '\n\n\n'
	certlist = '\n'.join(templist)
	# print(certlist)
	global trusted_list
	trusted_list = {}

	for line in certlist.split('\n\n\n'):
		for field in line.split('\n'):
			if 'Alias' in field:
				error = ""
				result = bcolors.OKGREEN + "\t[PASS]" + bcolors.ENDC
				alias = field.split()[2]
				VecsClient = GetVecs()
				cert = VecsClient.GetVecsCert('TRUSTED_ROOTS',alias)
				parsed_cert = Cert(cert)
				# print(parsed_cert)
				rootentry = {'subject': parsed_cert.subject, 'subjectkey':parsed_cert.subjectkey, 'thumbprint': parsed_cert.thumbprint, 'authkey': parsed_cert.authkey }
				trusted_list[alias] = rootentry

def checkRoots():
	print(color_wrap("\nChecking TRUSTED_ROOTS certificates\n",'subheading'))
	certlist = run_command(["/usr/lib/vmware-vmafd/bin/vecs-cli", "entry", "list", "--store", "TRUSTED_ROOTS"]).decode()
	for line in certlist.split('\n\n\n'):
		for field in line.split('\n'):
			if 'Alias' in field:
				error = ""
				result = bcolors.OKGREEN + "\t[PASS]" + bcolors.ENDC
				alias = field.split()[2]
				VecsClient = GetVecs()
				cert = VecsClient.GetVecsCert('TRUSTED_ROOTS',alias)
				print("  Alias: %s" % alias)
				certlook = checkCert(cert, alias=alias, note="TRUSTED_ROOTS ENTRY")
				certlook.execute(san=False)
				if not certlook.caCheck():
					result = bcolors.FAIL + "\t[FAIL]" + bcolors.ENDC
					error = "Certificate %s in TRUSTED_ROOTS is NOT a CA!  It must be removed.  Please see https://kb.vmware.com/s/article/2146011" % field
					# add command to verify the cert, add caveat that if it is a vasa provider, it should remain (or the provider will go offline)
				else:
					result = bcolors.OKGREEN + "\t[PASS]" + bcolors.ENDC
				msg = "Certificate is a CA\n"
				formResult(result, msg)
				if error != "":
					print(error)

def checkMACHINE_SSL_CERT():
	print(color_wrap("Checking MACHINE_SSL_CERT\n",'subheading'))
	myip,myhostname = getAddr()
	VecsClient = GetVecs()
	cert = VecsClient.GetVecsCert('MACHINE_SSL_CERT','__MACHINE_CERT')
	checkCert(cert,myhostname,myip,alias='MACHINE_SSL_CERT').execute()

def checkCerts(username="",password=""):
	myip,myhostname = getAddr()
	print(color_wrap("\nChecking Other Certificate Stores",'subheading'))
	storeignore = ['TRUSTED_ROOTS', 'TRUSTED_ROOT_CRLS', 'MACHINE_SSL_CERT', 'APPLMGMT_PASSWORD', 'KMS_ENCRYPTION']

	VecsClient = GetVecs(ignore_list=storeignore)
	certs = VecsClient.all()
	for store in certs:
		if store not in storeignore:
			logger.debug("Checking certs in store: %s" % store)
			if len(certs[store].keys()) > 0:
				print("\n    %s" % store.upper())
				if 'BACKUP_STORE' in store:
					formResult(color_wrap("\tNOTE: ",'info'), "If you do not need your old certs, you can delete this store."
						"\n\tCommand:  /usr/lib/vmware-vmafd/bin/vecs-cli store delete --name BACKUP_STORE\n")
					# print("\tNOTE:  If you do not need your old certs, you can delete this store."
					# 	"\n\tCommand:  /usr/lib/vmware-vmafd/bin/vecs-cli store delete --name BACKUP_STORE\n")
					continue
				for alias in certs[store]:
					logger.debug("Checking cert alias %s in store %s" % (alias, store))
					try:
						cert = certs[store].get(alias)
						if 'wcp' in store or 'wcp' in alias:
							checkCert(cert,myhostname,myip,alias=alias).execute(san=False)
						elif 'KMS_ENCRYPTION' in store and 'password' not in alias:
							try:
								checkCert(cert,myhostname,myip,alias=alias).execute(alg=True,exp=True,san=False,ca=False,trust=False,extusage=False)
							except:
								print("There was a problem checking KMS certs.  Skipping...")
								pass
						else:
							if 'SMS' in store:
								checkCert(cert,myhostname,myip,alias=alias).execute(trust=False, san=False)
							else:
								# checkCert(cert,myhostname,myip,alias=alias).execute()
								# print("Checking if vpxd-extension in alias: %s or store: %s" % (alias, store))
								if 'vpxd-extension' in alias or 'vpxd-extension' in store:
									# print("Found vpxd-extension.")
									logger.info("Found vpxd-extension.")
									checkCert(cert,myhostname,myip,alias=alias).execute(extusage=True)
									if username != "" and password != "":
										checkExtCerts(username,password)
								else:
									checkCert(cert,myhostname,myip,alias=alias).execute()
						
					except Exception as e:
						print("skipping %s, error was: %s" % (alias, e))
						continue

def checkVmdirCert():
	nodetype = getNodeType()
	if nodetype == 'embedded' or nodetype == 'infrastructure':
		certlocation = "/usr/lib/vmware-vmdir/share/config/vmdircert.pem"
		if os.path.exists(certlocation):
			print(color_wrap("Checking local LDAP cert",'subheading'))
			logger.debug("Found vmdir cert: %s" % certlocation)
			cert = open(certlocation,"r").read()
			print("\n    VMDIR CERT")
			checkCert(cert,alias="vmdir").execute(alg=False,exp=True,san=False,ca=False,trust=False)
			print("")

def displayCertMode(username,password):
	nodetype = getNodeType()
	result = color_wrap("[PASS]", "pass")
	msg = ""
	if password != "":
		if nodetype == 'embedded' or nodetype == 'management':
			if test_login(username, password):
				client = exManager(username,password)
				certmode = client.getSetting('vpxd.certmgmt.mode')
				if certmode == "thumbprint":
					result = color_wrap("[FAIL]", 'fail')
					msg = """\tVMware does not recommend using the value of 'thumbprint' for 
		the vpxd.certmgmt.mode advanced Setting for extended periods.  
		It is recommended to change the value to the default 'vmca', 
		or 'custom',depending on your security requirements.  
		Changing to one of these values will require that certificates 
		be re-issued to the hosts.  See 'Renew or Refresh ESXi Certificates' 
		section of the vSphere Security documentation.
					"""
				title = "ESXi Certificate Management Mode: %s\n" % certmode
				formResult(result, title)
				if msg != "":
					print(msg)
			else:
				formResult(color_wrap("[WARN]","warn"), "ESXi Certificate Management Mode: Login Failure")
	else:
		formResult(color_wrap("[INFO]",'info'), "Skipped certificate management node check due to empty credentials.\n")

def checkSTS():
	print(color_wrap("Checking STS Certs\n",'subheading'))
	error = ""
	try:
		parse_sts = parseSts()
	except:
		print(color_wrap("Failed to contacting STS service.  Are the STS services running?", 'fail'))
		raise
	results = parse_sts.execute()
	valid_count = len(results['valid']['leaf']) + len(results['valid']['root'])
	expired_count = len(results['expired']['leaf']) + len(results['expired']['root'])
	result = bcolors.OKGREEN + "\t[PASS]" + bcolors.ENDC
	if expired_count > 0:
		result = bcolors.FAIL + "\t[FAIL]" + bcolors.ENDC
		error = "You have expired STS certificates.  Please see %s" % vcsa_kblink

	msg = "Certificate expiration check"
	formResult(result,msg)
	if error != "":
		print(error)

def main(username="", password=""):
	# if not commanded:
	# 	username = os.environ["VDT_USERNAME"]
	# 	password = os.environ["VDT_PASSWORD"]
	displayCertMode(username, password)
	getCaTrustList()
	checkMACHINE_SSL_CERT()
	checkCerts(username,password)
	checkRoots()
	checkVmdirCert()
	try:
		checkSTS()
	except Exception as e:
		formResult("\t" + color_wrap("[FAIL]",'fail'), "Is STS started?  Error was:%s" % e)
		# print("\tFailed STS check.  Is STS started?  \n\tError was:%s" % e)
		sys.exit(1)

def main_wrap(username="", password=""):
	setupLogging()
	# print(color_wrap("VC CERTIFICATE CHECK",'title'))
	req_service = 'vmafdd'
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

