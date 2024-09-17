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
__title__ = "VC SERVICES CHECK"
import os
import contextlib
import atexit
import argparse
import ast
import getpass
import sys
import ssl
import time
import subprocess
from datetime import datetime, timedelta
parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
libdir = os.path.abspath(os.path.join(parentdir, 'lib'))
sys.path.append(libdir)
sys.path.append(os.environ['VMWARE_PYTHON_PATH'])
from pformatting import *
from cis.svcsController import get_services_status
from cisutils import getSrvStartType
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vdt import setupLogging
import logging
logger = logging.getLogger(__name__)

# from utils import get_params, exec_batch
from multiprocessing import cpu_count
_DefaultCommmandEncoding = sys.getfilesystemencoding()


def supress_stderr(func):
    def wrapper(*a, **ka):
        with open(os.devnull, 'w') as devnull:
            with contextlib.redirect_stderr(devnull):
                func(*a, **ka)
    return wrapper

def run_command(cmd, stdin=None, quiet=False, close_fds=False,
				encoding=_DefaultCommmandEncoding, log_command=True):

	process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
							stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	if sys.version_info[0] >= 3 and isinstance(stdin, str):
		stdin = stdin.encode(encoding)
	stdout, stderr = process.communicate(stdin)
	return stdout.decode()

# @supress_stderr
def getStartup(service):
	result = ""
	if 'vmware-' in service and 'postgres' not in service and 'sts' not in service:
			service = service.replace('vmware-', '')
			if 'watchdog' in service:
				service = service.replace('-watchdog','')
	try:
		result = str(getSrvStartType(service,quiet=True))
	except:
		result = "Automatic"
	if not result:
		result = "Automatic"

	# print("PRINTING " + result)
	return result

def main():

	services = get_services_status(None)
	failflag = 0
	alarms = []
	success = []
	for x,y in services.items():
		auto = 0


		if len(y) == 2:
			status = y[0]
		else:
			status = y
		if status != 'RUNNING':
			# print("PRINTING" + x)
			startup = getStartup(x)
			
			# print("PRINT " + str(startup))
			if startup == "Automatic" or startup == "Unknown":
				failflag = 1
				msg = bcolors.FAIL + "[FAIL]" + bcolors.ENDC
				msg = "\t" + msg + '\t' + x + " IS " + status
				alarms.append(msg)
		else:
			success.append(x)
	if len(success) < 1:
		print("ALL SERVICES STOPPED")
	else:
		if len(alarms) > 0:
			for x in alarms:
				print(x)
	if failflag:
		result = bcolors.FAIL + "[FAIL]" + bcolors.ENDC
	else:
		result = bcolors.OKGREEN + "[PASS]" + bcolors.ENDC
	print("\nRESULT: %s" % result)

if __name__ == '__main__':
	setupLogging()
	# print(color_wrap("VC SERVICES CHECK",'title'))
	message = """Printing only services that are stopped and should be started.
KB: https://kb.vmware.com/s/article/2109887
"""
	print(message)
	main()