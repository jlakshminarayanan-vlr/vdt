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


--------
Library with classes/functions to work with certs and PSC
services.

"""
def formResult(result, msg):
    print("%s\t%s" % (result,msg))

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    INFO = '\033[96m'
    OKCYAN = '\033[4;96m'
    OKGREEN = '\033[32m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def color_wrap(input_string, heading):

    if heading == 'title':
        length = len(input_string)
        length = length + 6
        topline = '_' * length
        new_string = bcolors.OKCYAN + topline + "\n   " + input_string + "   \n" + bcolors.ENDC
        return new_string
    
    if heading == "subheading":
        return bcolors.BOLD + input_string + bcolors.ENDC
    
    if heading == "fail":
        return bcolors.FAIL + input_string + bcolors.ENDC

    if heading == "pass":
        return bcolors.OKGREEN + input_string + bcolors.ENDC

    if heading == "warn":
        return bcolors.WARNING + input_string + bcolors.ENDC

    if heading == "info":
        return bcolors.INFO + input_string + bcolors.ENDC