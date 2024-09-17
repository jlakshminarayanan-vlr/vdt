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
TITLE = "CHECK TITLE"
REQUIRED_SERVICE = "vmdird"

import os
import sys
sys.path.append(os.environ['VMWARE_PYTHON_PATH'])
parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
libdir = os.path.join(parentdir, 'lib')
sys.path.append(os.path.abspath(libdir))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pformatting import *
from utils import getSingleServiceStatus, getStartup
from vdt import setupLogging
import logging
logger = logging.getLogger(__name__)

def main_function():

	print(color_wrap("title format",'title'))
	print(color_wrap("subheading format",'subheading'))
	print(color_wrap("failure color",'fail'))
	print(color_wrap("pass color",'pass'))
	print(color_wrap("warn color",'warn'))
	print(color_wrap("info color",'info'))

	result1 = color_wrap("[FAIL]",'fail')
	result2 = color_wrap("[PASS]", 'pass')

	formResult(result1, "Example failure check description")
	formResult(result2, "Example pass check description")

if __name__ == '__main__':
	setupLogging()
	TITLE = color_wrap(TITLE,'title')
	print(TITLE)
	req_service = REQUIRED_SERVICE
	service_status = getSingleServiceStatus(req_service)
	service_startup = getStartup(req_service)
	if service_status and service_startup == 'Automatic':
		main_function()
	elif service_status and service_startup != 'Automatic':
		print('Service: %s is disabled.' % req_service)
	elif not service_status and service_startup == 'Automatic':
		formResult(color_wrap("[FAIL]", 'fail'), "Service: %s is not started! It is required for this test to run." % req_service)
	else:
		formResult(color_wrap("[INFO]", 'info'), "Service: %s is not started.  Is it configured and running?" % req_service)