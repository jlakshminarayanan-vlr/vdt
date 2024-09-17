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
__title__ = "Root Account Check"
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
parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
libdir = os.path.join(parentdir, 'lib')
sys.path.append(os.path.abspath(libdir))
from pformatting import *
from utils import getSingleServiceStatus, getStartup
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vdt import setupLogging
import logging
logger = logging.getLogger(__name__)
NUM_DAYS_CRITICAL = 30
NUM_DAYS_WARNING = 60
NUM_DAYS_INFO = 90
CHECKS = {"CRITICAL" : NUM_DAYS_CRITICAL,
		"WARNING": NUM_DAYS_WARNING, 
		"INFO": NUM_DAYS_INFO}

today = datetime.now()
today = today.strftime("%b %d, %Y")

_DefaultCommmandEncoding = sys.getfilesystemencoding()

def run_command(cmd, stdin=None, quiet=False, close_fds=False,
				encoding=_DefaultCommmandEncoding, log_command=True):

	process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
							stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	if sys.version_info[0] >= 3 and isinstance(stdin, str):
		stdin = stdin.encode(encoding)
	stdout, stderr = process.communicate(stdin)
	return stdout

def getPassExpire():
	help_msg = "\n\tPlease search for 'Change the Password of the Root User' \n\tin vCenter documentation."
	error = ""
	expire = ""
	failflag = False
	cmd = ['/usr/bin/chage', '-l', 'root']
	raw_data = run_command(cmd).decode()
	for line in raw_data.splitlines():
		if 'Password expires' in line:
			expire = line.strip().split(':')[1].lstrip()
	if expire == 'never':
		msg = "Root password never expires"
		result = color_wrap("[PASS]",'pass')
	else:
		exp_date = datetime.strptime(expire, '%b %d, %Y')
		now = datetime.strptime(today, '%b %d, %Y')
		diff = exp_date - now
		exp_in_days = diff.days

		if exp_date <= now + timedelta(days=CHECKS.get("CRITICAL")):
			result = color_wrap("[FAIL]",'fail')
			failflag = True

		elif exp_date <= now + timedelta(days=CHECKS.get("WARNING")):
			result = color_wrap("[WARN]",'warn')
			failflag = True

		elif exp_date <= now + timedelta(days=CHECKS.get("INFO")):
			result = color_wrap("[INFO]",'info')
			failflag = True
		else:
			result = color_wrap("[PASS]",'pass')
		
		msg = "Root password expires in %s days" % exp_in_days
	formResult(result,msg)
	if failflag:
		print(help_msg)


def main():
	getPassExpire()

if __name__ == '__main__':
	setupLogging()
	# print(color_wrap("Root Account Check", 'title'))
	main()
