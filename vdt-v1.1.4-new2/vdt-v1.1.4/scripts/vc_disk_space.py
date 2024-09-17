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
__title__ = "DISK CHECK"
import shutil
import subprocess
import os
import sys
import stat
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
libdir = os.path.join(parentdir, 'lib')
sys.path.append(os.path.abspath(libdir))
from pformatting import *
from vdt import setupLogging
import logging
logger = logging.getLogger(__name__)

threshold = 80
testkb="https://kb.vmware.com/s/article/1003564"
class disk_stat(object):
    pass

def inodes(raw_data,exclude=None):
    
    rc = 0
    msg_thresh = "%" + str(threshold)
    alarms = []

    list_mounts = [x for x in raw_data.strip().split('\n')[2:]]
    if exclude:
        list_mounts = [mount for mount in list_mounts if not any(excl in mount for excl in exclude)]
    for mount in list_mounts:
        # print(mount)
        stats = disk_stat()
        stats.mount = mount.split()[5]
        stats.total = int(mount.split()[1])
        stats.used = int(mount.split()[2])

        if stats.used != 0:
            perc = stats.used/stats.total*100
            perc = round(perc)
        
        #return a string with a percent sign in front
        output = "%" + str(perc)

        #return a message that's useful
        if perc >= threshold:
            msg = "\tWARNING - Used inodes on %s is %s which is over the threshold of %s used" % (stats.mount, output, msg_thresh)
            alarms.append(bcolors.WARNING + msg + bcolors.ENDC)
    if len(alarms) > 0:
        result = "\n" + bcolors.FAIL + "[FAIL]" + bcolors.ENDC
        msg = color_wrap("INODE USAGE",'subheading')
        formResult(result,msg)
        alarmmsg = '\n\t'.join([alarm for alarm in alarms])
        print("\t" + bcolors.WARNING + alarmmsg + bcolors.ENDC)
        rc = 1
    else:
        result = "\n" + bcolors.OKGREEN + "[PASS]" + bcolors.ENDC
        msg = color_wrap("INODE USAGE",'subheading')
        formResult(result,msg)
    
    return rc

def get_directory_size(directory):
    """Returns the `directory` size in bytes."""
    total = os.path.getsize(directory)
    for entry in os.listdir(directory):
        entry_path = os.path.join(directory, entry)
        try:
            if os.path.isfile(entry_path):
                # if it's a file, use stat() function
                total += os.path.getsize(entry_path)
            elif os.path.isdir(entry_path):
                total += get_directory_size(entry_path)
        except NotADirectoryError:
            # if `directory` isn't a directory, get the file size then
            print(logdir_path)
            print("NOT A DIR: %s" % str(os.path.getsize(logdir_path)))
            return os.path.getsize(logdir_path)
        except PermissionError:
            # if for whatever reason we can't open the folder, return 0
            pass
    return total

def format_size(number):
    sizeform = "MB"
    filesize = number/(1024*1024)
    if filesize > 1024:
        sizeform = "GB"
        filesize = number/(1024*1024*1024)
    filesize = str(round(filesize,2)) + sizeform
    return filesize

def get_largest_files(directory):
    print("\t\tLargest Files:")
    file_list = []
    for root,dirs,files in os.walk(directory):
        for file in files:
            if 'proc' not in file:
                filepath = os.path.join(root, file)
                file_list.append((filepath, os.path.getsize(filepath)))
    file_list.sort(key = lambda x: x[1], reverse=True)
    file_list = file_list[:5]
    for order, file in enumerate(file_list):
        print("\t\t- %s %s" % (file[0], format_size(file[1])))

def get_largest_dir(mount):
    print("\tDirectories over 2GB:\n")
    sizes = []
    sizes.append((mount, get_directory_size(mount)))
    for directory in os.listdir(mount):
        dir_path = os.path.join(mount, directory)
        if os.path.isdir(dir_path):
            sizes.append((dir_path, get_directory_size(dir_path)))
    sizes.sort(key = lambda x: x[1], reverse=True)
    sizes = sizes[:5]
    for order, folder in enumerate(sizes):
        if folder[1] > 2147483648:
            print("\t[] " + folder[0], format_size(folder[1]))
            get_largest_files(folder[0])
            print("")

def space(raw_data, exclude=None):

    rc = 0
    msg_thresh = "%" + str(threshold)
    alarms = []
    list_mounts = [x for x in raw_data.strip().split('\n')[2:]]
    if exclude:
        list_mounts = [mount for mount in list_mounts if not any(excl in mount for excl in exclude)]

    for mount in list_mounts:
        stats = disk_stat()
        stats.mount = mount.split()[5]
        #take the mount point that was passed to me, give me disk usage
        stats.used = int(mount.split()[2])
        stats.free = int(mount.split()[3])
        stats.total = stats.free + stats.used

        #get usage by dividing used by total, round to the nearest 2 places
        perc = stats.used/stats.total*100
        perc = round(perc)
        
        #return a string with a percent sign in front
        output = "%" + str(perc)

        #return a message that's useful
        if perc >= threshold:
            msg = "\tWARNING - disk space on %s is %s which is over the threshold of %s used.  See details:" % (stats.mount, output, msg_thresh)
            alarms.append((bcolors.WARNING + msg + bcolors.ENDC, stats.mount))
            
    if len(alarms) > 0:
        result = bcolors.FAIL + "[FAIL]" + bcolors.ENDC
        msg = color_wrap("DISK CAPACITY",'subheading')

        formResult(result,msg)
        for msg, mount in alarms:
            print(msg)
            get_largest_dir(mount)
        rc = 1
    else:
        result = bcolors.OKGREEN + "[PASS]" + bcolors.ENDC
        msg = color_wrap("DISK CAPACITY",'subheading')
        formResult(result,msg)
    
    return rc

def getFilesystems(function):
    #list object that contains the mount points
    filesystems = []

    #runs the command
    if function == 'space':
        cmd = ['df']
    if function == 'inodes':
        cmd = ['df', '-i']
    diskinfo = subprocess.Popen(cmd, stdout = subprocess.PIPE)
    output = diskinfo.communicate()[0]

    #decodes it from bytes to string
    output = output.decode()

    #return the list of mounts
    return output

def main():

    failflag = False
    # print(color_wrap("DISK CHECK",'title'))

    space_details = getFilesystems('space')
    inode_details = getFilesystems('inodes')
    exclusion = ['archive']

    if space(space_details,exclusion):
        failflag = True

    if inodes(inode_details,exclusion):
        faiflag = True

    if failflag:
        result = bcolors.FAIL + "[FAIL]" + bcolors.ENDC
    else:
        result = bcolors.OKGREEN + "[PASS]" + bcolors.ENDC
    print("\nRESULT: %s" % result)
    print("Please see KB: %s" % testkb)

if __name__ == '__main__':
    setupLogging()
    main()
