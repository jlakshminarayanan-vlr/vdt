#!/usr/bin/env python3
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
__title__ = "CORE FILE CHECK"
import shutil
import subprocess
import os
import sys
import fnmatch
import stat
from datetime import datetime, timedelta
import time
import json
import glob
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
libdir = os.path.join(parentdir, 'lib')
sys.path.append(os.path.abspath(libdir))
from pformatting import *
from vdt import setupLogging
import logging
logger = logging.getLogger(__name__)

today = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

threshold = 80
testkb="https://kb.vmware.com/s/article/1003564"
NUM_HOURS_CRITICAL = 12
CRITICAL_MESSAGE = """

These corefiles have been created within the last %s hours.  
Investigation is warranted. 

""" % NUM_HOURS_CRITICAL

NUM_HOURS_WARNING = 72
WARNING_MESSAGE = """ 

These core files have been created within %s to %s hours.
Investigation only warranted if there are many from the same service
and you are experiencing symptoms.  Otherwise, consider deleting them
at your discretion to reduce the size of log bundles.

""" % (NUM_HOURS_CRITICAL, NUM_HOURS_WARNING)

NUM_HOURS_INFO = None
INFO_MESSAGE = """ 

These core files are older than %s hours.  consider deleting them
at your discretion to reduce the size of log bundles.

""" % NUM_HOURS_WARNING




def evalRelevancy(files):
    highest_fail = 0
    
    CHECKS = {"CRITICAL" : 
        {"duration": NUM_HOURS_CRITICAL,
            "message" : CRITICAL_MESSAGE,
            "failstate" : 2,
            "files": []},
        "WARN": 
            {"duration": NUM_HOURS_WARNING,
            "message" : WARNING_MESSAGE,
            "failstate": 1,
            "files": []},
        "INFO": 
            {"duration": NUM_HOURS_INFO,
            "message" : INFO_MESSAGE,
            "failstate" : 0,
            "files": []}
        }

    def check_exists(filedetail):
        for check in CHECKS:
            if filedetail in CHECKS[check]['files']:
                return True
        return False

    def is_file_older(filename, delta):
        cutoff = datetime.utcnow() - delta
        mtime = datetime.utcfromtimestamp(os.path.getmtime(file))

        if mtime > cutoff:
            return True
        return False

    for file in files:
        now = datetime.now()
        last_modified = getLastModifiedDate(file)
        time = os.path.getmtime(file)
        # time = datetime.strptime(time,'%Y-%m-%dT%H:%M:%S')
        size = getFileSize(file)
        if is_file_older(file, timedelta(hours=CHECKS["CRITICAL"].get("duration"))):
            # print("%s is greater than %s" %(time, now + timedelta(hours=CHECKS["CRITICAL"].get("duration"))))
            if CHECKS["CRITICAL"].get("failstate") > highest_fail:
                highest_fail = CHECKS["CRITICAL"].get("failstate")
            filedetail = "\t%s Size: %s Last Modified: %s" % (file, size, last_modified)
            if not check_exists(filedetail):
                CHECKS["CRITICAL"]['files'].append(filedetail)
            continue

        if is_file_older(file, timedelta(hours=CHECKS["WARN"].get("duration"))):
            # print("%s is greater than %s" %(time, now + timedelta(hours=CHECKS["WARN"].get("duration"))))
            if CHECKS["WARN"].get("failstate") > highest_fail:
                highest_fail = CHECKS["WARN"].get("failstate")
            filedetail = "\t%s Size: %s Last Modified: %s" % (file, size, last_modified)
            if not check_exists(filedetail):
                CHECKS["WARN"]['files'].append(filedetail)
            continue
        
        # print("LAST TOUCH: %s, NOW: %s" % (time, now))
        filedetail = "\t%s Size: %s Last Modified: %s" % (file, size, last_modified)
        if not check_exists(filedetail):
            CHECKS['INFO']['files'].append(filedetail)
    return highest_fail, CHECKS

def listCoreFiles(dirname, proc):
    for root,dirs,files in os.walk(dirname):
            for name in files:
                if 'core' in name and proc in name:
                    yield os.path.join(root,name)

def getMostRecent(dirname,proc):
    latest = max(listCoreFiles(dirname,proc), key=os.path.getmtime)
    return latest

def getLastModifiedDate(filename):
    mod_time = os.path.getmtime(filename)
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(mod_time))

def getFileSize(filename):
    
    original_size = os.path.getsize(filename)
    sizeform = "MB"
    filesize = original_size/(1024*1024)
    if filesize > 1024:
        sizeform = "GB"
        filesize = original_size/(1024*1024*1024)
    filesize = str(round(filesize,2)) + sizeform
    return filesize

def searchFiles(directory, pattern, ignorelist=[]):
    
    filelist = []
    for root, dirnames, filenames in os.walk(directory):
        if not any(ignore in root for ignore in ignorelist):
            for filename in fnmatch.filter(filenames, pattern):
                filelist.append(os.path.join(root, filename))
    return filelist

def findHprofs():

    end_result = color_wrap("\n[PASS]", 'pass')
    fail_flag = False
    vmware_log_path = '/var/log/vmware'
    core_path = '/storage/core'
    hprof_list = searchFiles(vmware_log_path, '*hprof*')
    hprof_list.extend(searchFiles(core_path, '*hprof*'))

    result_list = []
    hprof_count = len(hprof_list)
    msg = "Number of hprof files: %s" % str(hprof_count)
    title = color_wrap(msg,'subheading')
    if hprof_count > 0:
        hprof_list = sorted(hprof_list, key=lambda f: -os.stat(f).st_mtime)
        highest_fail, checks = evalRelevancy(hprof_list)

        if len(checks['CRITICAL']['files']) > 0:
            fail_flag = True
            print("\n%s:  %s" % (color_wrap("CRITICAL", 'fail'), checks['CRITICAL']['message']))
            print("  FILES:\n    %s" % "\n    ".join([x for x in checks['CRITICAL']['files']]))
        
        if len(checks['WARN']['files']) > 0:
            fail_flag = True
            print("\n%s:  %s" % (color_wrap("WARN", 'warn'), checks['WARN']['message']))
            print("  FILES:\n    %s" % "\n    ".join([x for x in checks['WARN']['files']]))
        
        if len(checks['INFO']['files']) > 0:
            fail_flag = True
            print("\n%s:  %s" % (color_wrap("INFO", 'info'), checks['INFO']['message']))
            print("  FILES:\n    %s" % "\n    ".join([x for x in checks['INFO']['files']]))
        
        if highest_fail >= 1:
            end_result = color_wrap("\n[WARN]", 'warn')
        if highest_fail == 0:
            end_result = color_wrap("\n[INFO]", 'info')
    formResult(end_result, title)

def checkCores():
    end_result = color_wrap("\n[PASS]", 'pass')
    fail_flag = False
    core_path = '/storage/core'
    core_list = searchFiles(core_path, 'core*', ignorelist=['software-update'])
    result_list = []

    core_count = len(core_list)
    msg = "Number of core files: %s" % str(core_count)
    title = color_wrap(msg,'subheading')
    if core_count > 0:
        core_list = sorted(core_list, key=lambda f: -os.stat(f).st_mtime)
        highest_fail, checks = evalRelevancy(core_list)

        if len(checks['CRITICAL']['files']) > 0:
            fail_flag = True
            print("\n%s:  %s" % (color_wrap("CRITICAL", 'fail'), checks['CRITICAL']['message']))
            print("  FILES:\n    %s" % "\n    ".join([x for x in checks['CRITICAL']['files']]))
        
        if len(checks['WARN']['files']) > 0:
            fail_flag = True
            print("\n%s:  %s" % (color_wrap("WARN", 'warn'), checks['WARN']['message']))
            print("  FILES:\n    %s" % "\n    ".join([x for x in checks['WARN']['files']]))
        
        if len(checks['INFO']['files']) > 0:
            fail_flag = True
            print("\n%s:  %s" % (color_wrap("INFO", 'info'), checks['INFO']['message']))
            print("  FILES:\n    %s" % "\n    ".join([x for x in checks['INFO']['files']]))
        
        if highest_fail >= 1:
            end_result = color_wrap("\n[WARN]", 'warn')
        if highest_fail == 0:
            end_result = color_wrap("\n[INFO]", 'info')
    formResult(end_result, title)  
        
if __name__ == '__main__':
    setupLogging()
    # print(color_wrap("CORE FILE CHECK", 'title'))
    checkCores()
    findHprofs()