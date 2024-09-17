#!/usr/bin/env python

"""
Copyright (C) 2021 VMware, Inc.

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

SPDX-License-Identifier: MIT
"""

import json
import os
import sys
import subprocess
import re
import time
import errno
import random
import string
import codecs
import logging
import logging.handlers
import platform
import six
from datetime import datetime
sys.path.append(os.environ['VMWARE_PYTHON_PATH'])

if os.name != 'posix':
   import pywintypes
   import win32con
   import win32service
   import win32serviceutil
   import win32api
   import winerror
   import win32process
   import win32security
   import win32event
   try:
      import winreg as _winreg  # Python 3 hack
   except ImportError:
      import _winreg

if sys.version_info[0] >= 3:
    # Python3 hack.
    import ipaddress as ipaddr
    ipaddr.IPAddress = ipaddr.ip_address
else:
    import ipaddr

if sys.version_info[0] >= 3 and os.name != 'posix':
    import _winapi

DEF_ENCODING = 'utf-8'
WIN_ENCODING = 'mbcs'

try:
    unicode  # Python 3 hack
except NameError:
    unicode = str

try:
   osIsSles12 = platform.linux_distribution()[1].startswith('12')
except AttributeError:
   osIsSles12 = False

try:
   osIsPhoton = os.path.isfile('/etc/photon-release')
except AttributeError:
   osIsPhoton = False

osIsSystemd = osIsSles12 or osIsPhoton

_systemctl_path = '/usr/bin/systemctl'

from cis.exceptions import *
from cis.defaults import (def_by_os, get_cis_config_dir,
                          get_cis_install_dir, get_vmon_cli_path)
from cis.l10n import localizedString
from cis.msgL10n import MessageMetadata as _T
from cis.baseCISException import BaseInstallException
from cis.componentStatus import ErrorInfo
from cis.svcscfg import (loadServicesFile, genDepTracker,
                         isInstalledService, platform)

# vmon cli's rc value and it's reason code
class vMonError:
    VMON_ERRNO_SUCCESS = 0
    VMON_ERRNO_TIMEOUT = 1
    VMON_ERRNO_SERVICE_CRASHED = 2
    VMON_ERRNO_INTERRUPTED = 3
    VMON_ERRNO_SYSTEM_ERR = 4
    VMON_ERRNO_INVALID_STATE = 5
    VMON_ERRNO_INVALID_INPUT = 6
    VMON_ERRNO_UNSUPPORTED = 7
    VMON_ERRNO_INVALID_REQUEST = 8
    VMON_ERRNO_SVC_DISABLED = 9
    VMON_ERRNO_INVALID_PROFILE = 10
    VMON_ERRNO_VMON_UNAVAILABLE = 11
    VMON_ERRNO_UNUSED_LAST = 12

# Class for logging
class setupLogging:
   """
   Initializes the format for logging, and the then sets up the logging handler, defaulting to syslog when it is available.

   Arguments:-
   program: program name
   level: logging level (logging.INFO, logging.DEBUG, etc)
   logMechanism: default is syslog, but specify either syslog, file, or stdout/stderr when you want to force to log to one of them explicitly
   logDir: when logging to file, this is the dir where the log file will be created
   rotate_bytes: Size of logfile after which to rollover.
   rotate_count: maximum number of old log files to save.

   Note: Please note that although the support for file rotation is present, it
   should be used carefully. If different users are allowed to run the script
   for which the logger is being used, please do make sure to give proper permissions.
   The different users should be part of a group and the log directories gid bit
   should be set so that the files created inside the dir inherit the directories group.
   In the logger, we give the owner and group of the file write permissions.
   """
   # Constructor takes params that identify the log mechanism (syslog/file/stdout) and if none is provided, it defaults to syslog
   def __init__(self, program, level=logging.INFO, logMechanism='syslog',
                logDir=None, rotate_bytes=0, rotate_count=0):
      if logDir is None:
         # Set to default value
         logDir = os.environ['VMWARE_LOG_DIR']
      self._initLogFormat(program, level, logDir=logDir)
      if os.name == 'posix' and logMechanism == 'syslog':
         try:
            self.rootLogger.handlers = []
            syslogHandler = logging.handlers.SysLogHandler('/dev/log')
            # XXX The default SysLogHandler appends a zero-terminator, which vmsyslogd
            # does not consume and puts in the log file.
            syslogHandler.log_format_string = '<%d>%s'
            syslogHandler.setFormatter(logging.Formatter(self.logFormat, datefmt=self.dateFmt))
            self.rootLogger.addHandler(syslogHandler)
            logging.debug("Logging to syslog")
            return
         except:
            # Continue to setup another logging mechanism
            log_error("Syslog service is stopped. Logging to file instead.\n")
      # If primary logging mechanism is specified as stream, direct logs to stdout/stderr
      if logMechanism == 'stdout' or logMechanism == 'stderr':
         self._setupStreamLogging(program, level, logMechanism)
         return
      # Else, log to file
      self._setupFileLogging(program, level=level, logDir=logDir,
         rotate_bytes=rotate_bytes, rotate_count=rotate_count)

   # initalize the logging format
   def _initLogFormat(self, program, level, logDir):
      # make sure the log directory exists
      create_dir(logDir)

      logging.Formatter.converter = time.gmtime
      self.rootLogger = logging.getLogger()
      # set up the root logger level
      self.rootLogger.setLevel(level)

      # Initializing log format (Datetime: UTC ISO 8601 format)
      self.logFormat = "%(asctime)s.%(msecs)dZ %(levelname)s " + program + " %(message)s"
      self.dateFmt = "%Y-%m-%dT%H:%M:%S"

   # set up logging to file
   def _setupFileLogging(self, program, level, logDir, rotate_bytes,
                         rotate_count):
      logFile = os.path.join(logDir, '%s.log' % program)
      class GroupWriteRotatingFileHandler(logging.handlers.RotatingFileHandler):
         def _open(self):
            # We need the group to have write permissions
            prevumask = os.umask(0o002)
            rtv = logging.handlers.RotatingFileHandler._open(self)
            os.umask(prevumask)
            return rtv

      if rotate_bytes > 0 and rotate_count > 0:
         fileHandler = GroupWriteRotatingFileHandler(logFile,
            maxBytes=rotate_bytes, backupCount=rotate_count)
      else:
         fileHandler = logging.FileHandler(logFile)
      fileHandler.setFormatter(logging.Formatter(self.logFormat,
                               datefmt=self.dateFmt))
      self.rootLogger.addHandler(fileHandler)
      self.rootLogger.debug("Logging to file.")

   # set up logging to stdout/stderr
   def _setupStreamLogging(self, program, level, stream):
      # unless specified, default mode is to log to stdout
      if stream == 'stderr':
         streamHandler = logging.StreamHandler()
      else:
         streamHandler = logging.StreamHandler(sys.stdout)
      streamHandler.setFormatter(logging.Formatter(self.logFormat, datefmt=self.dateFmt))
      self.rootLogger.addHandler(streamHandler)
      self.rootLogger.debug("Logging to stdout")

def computeDatetimeUtc():
   """
   Function that returns the date-time in UTC ISO 8601 format
   """
   return '%sZ' % datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]


def baselog(stream, message, quiet=False):
   '''
   baselog function that takes a stream and message and logs the
   message to the stream correct format

   arguments:
      stream: file-like object that supports write
      message: object that supports __str__
      quiet: parameter that controls if string needs
             to be output to the stream
   '''
   if not quiet:
      # add two spaces at the end since we want
      # 3 spaces, 1 is added by print, this is done
      # to closely match default python logging format
      timestamp = '%s  ' % computeDatetimeUtc()
      stream.write(timestamp)
      try:
         stream.write(str(message))
      except UnicodeEncodeError:
         # if message cannot be directly encoded to ascii
         # call the unicode function which inturn calls
         # __unicode__ of message object which should return
         # a unicode string, if the object does not implement
         # __unicode__ the __str__ is called and encoded using
         # the default system encoding
         stream.write(unicode(message))
      stream.write('\n')
      stream.flush()

def log(message, quiet=False):
   """
   simple logging function
   """
   baselog(sys.stdout, message, quiet)

def log_error(message, quiet=False):
   """
   simple logging function for errors
   """
   baselog(sys.stderr, message, quiet)

def log_warning(message, quiet=False):
   """
   simple logging function for warnings
   """
   baselog(sys.stderr, message, quiet=False)


#
# Helper functions
#

def sleep_uninterruptible(secs):
    """
    Useful for making sure sleep is restarted on interrupt instead of throwing
    IOError exception.

    It should be a really corner case, but when we decide to move to python
    3.5 use montonic time instead of system clock time.
    """
    timetosleep = secs
    while True:
        starttime = time.time()
        try:
            time.sleep(timetosleep)
        except IOError as ex:
            if ex.errno == errno.EINTR:
                timetosleep -= time.time() - starttime
                if timetosleep > 0:
                    continue
        break

def get_chkconfig_cmd():
   """
   Gets the linux chkconfig binary location.
   """
   chkconfig_bin = "/sbin/chkconfig"
   return os.path.normpath(chkconfig_bin)

def get_svc_cmd():
   """
   Gets the service control binary location.
   """
   svc_cmd = def_by_os("/sbin/service", "sc.exe")
   return os.path.normpath(svc_cmd)

def is_windows():
   """
   simple function to check if the platform is windows
   """
   if os.name != 'posix':
      return True
   else:
      return False

def is_linux():
   """
   simple function to check if the platform is linux
   """
   if os.name == 'posix':
      return True
   else:
      return False

def create_dir(path):
   """
   helper method to create a directory
   """
   if not os.path.exists(path):
      try:
         os.makedirs(path)
      except OSError as e:
         if e.errno != errno.EEXIST:    # Already exists
            raise

def toUnicode(nonUniCodeStr):
    '''Method to encode string to unicode. If it cannot achieve that it will
    return the same string. The code is taken from upgraderunner
    (encoding_utils.py).

    @param nonUniCodeStr: String to decode
    @type str
    '''

    if nonUniCodeStr is None or not isinstance(nonUniCodeStr, six.binary_type):
        return nonUniCodeStr

    # Try with file system encoding, if it is not that, try with couple more
    # and after that give up
    try:
        return nonUniCodeStr.decode(sys.getfilesystemencoding())
    except (UnicodeDecodeError, LookupError):
        pass

    # if it is windows its more likely to succeed with mbcs, however if
    # that fails we will try with utf-8 and then give up
    if os.name != 'posix':
        try:
            return nonUniCodeStr.decode(WIN_ENCODING)
        except (UnicodeDecodeError, LookupError):
            pass

    # valid ascii is valid utf-8 so no point of trying ascii
    try:
        return nonUniCodeStr.decode(DEF_ENCODING)
    except (UnicodeDecodeError, LookupError):
        pass

    # cannot decode, return same string and leave the system to fail
    log_error('Tried to decode a string to unicode but it wasn\'t successful.'
              'Expecting system failures')
    return nonUniCodeStr

_DefaultCommmandEncoding = sys.getfilesystemencoding()

def invoke_command(cmd, stdin=None, quiet=False, close_fds=False,
                   encoding=_DefaultCommmandEncoding):
   """
   execute a command with the given input and throw an exception for non-zero
   return code
   """
   ret, stdout, stderr = run_command(cmd, stdin, quiet, close_fds, encoding)
   if ret != 0:
      log_error("Invoked command: " + str(cmd), quiet)
      log_error("RC = %s\nStdout = %s\nStderr = %s" % (ret, stdout, stderr))
      if not quiet:
         raise InvokeCommandException(errStr='Command: %s\nStderr: %s' %\
                                      (cmd, stderr))
      else:
         raise InvokeCommandException(errStr='Stderr: %s' % stderr)
   return stdout

def run_command(cmd, stdin=None, quiet=False, close_fds=False,
                encoding=_DefaultCommmandEncoding):
   """
   execute a command with the given input and return the return code and output
   """
   log("Running command: " + str(cmd), quiet)

   '''
   Note: close_fds is always set to False for windows. This is because
   stdin/stdout flags don't work with close_fds on Windows.
   '''
   close_fds = def_by_os(close_fds, False)
   process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, stdin=subprocess.PIPE,
                              close_fds=close_fds)
   if sys.version_info[0] >= 3 and isinstance(stdin, str):
      stdin = stdin.encode(encoding)
   stdout, stderr = process.communicate(stdin)
   stdout = toUnicode(stdout)
   stderr = toUnicode(stderr)
   log("Done running command", quiet)
   return process.returncode, stdout, stderr

def runCommand(command):
    """
    Execute the provided command and log stdout and stderr.

    Returns True if command has zero exit status.
    """
    rc, stdout, stderr = run_command(command)
    if rc != 0:
        log('ERROR: Command failed with exit status %d' % rc)
    if stdout != '':
        log('Stdout: %s' % stdout)
    # Suppress vami_login stderr since this is verbose logging
    if stderr != '' and stderr != 'vami_login: no process found\n':
        log('Stderr: %s' % stderr)
    return rc, stdout, stderr

def change_privilege(priv, enable=1):
    # Get the process token.
    flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
    htoken = win32security.OpenProcessToken(win32api.GetCurrentProcess(), flags)
    # Get the ID for the system privilege.
    idd = win32security.LookupPrivilegeValue(None, priv)
    priv = win32security.SE_PRIVILEGE_ENABLED if enable else 0
    newPrivileges = [(idd, priv)]
    win32security.AdjustTokenPrivileges(htoken, 0, newPrivileges)


class CisWinSubprocess(subprocess.Popen):
   """
   extending the subprocess popen class to provide support for running process
   as a user
   """
   def __init__(self, user, domain, password, args, stdin=None, stdout=None, stderr=None,
                close_fds=False):
      # Python 3 hack, string has no decode() function.
      if sys.version_info < (3,0,0) and isinstance(user, str):
          user = user.decode('utf-8')
      self._user = user
      # Python 3 hack, string has no decode() function.
      if sys.version_info < (3,0,0) and isinstance(domain, str):
          domain = domain.decode('utf-8')
      self._domain = domain
      # Python 3 hack, string has no decode() function.
      if sys.version_info < (3,0,0) and isinstance(password, str):
          password = password.decode('utf-8')
      self._password = password
      super(CisWinSubprocess, self).__init__(args, stdin=stdin, stdout=stdout,
                                             stderr=stderr, close_fds=close_fds)


   def _execute_child(self, args, executable, preexec_fn, close_fds,
                      cwd, env, universal_newlines,
                      startupinfo, creationflags, shell, to_close,
                      p2cread, p2cwrite,
                      c2pread, c2pwrite,
                      errread, errwrite):
      """
      override the _execute_child version of Popen to provide support for running
      as a user
      """
      if isinstance(args, list):
         args = subprocess.list2cmdline(args)

      # Process startup details
      # Clobber the 'startupinfo' function parameter explicitly.
      startupinfo = win32process.STARTUPINFO()
      if (None not in (p2cread, c2pwrite, errwrite) or
          -1 not in (p2cread, c2pwrite, errwrite)):
          startupinfo.dwFlags |= win32con.STARTF_USESTDHANDLES
          startupinfo.hStdInput = p2cread
          startupinfo.hStdOutput = c2pwrite
          startupinfo.hStdError = errwrite
      #
      # Define startupinfo structure
      # http://msdn.microsoft.com/en-us/library/windows/desktop/ms686331%28v=vs.85%29.aspx
      #
      startupinfo.dwFlags = startupinfo.dwFlags | win32con.STARTF_USESHOWWINDOW
      startupinfo.wShowWindow = win32con.SW_HIDE

      userToken = None
      try:
         # Login as the user and get user token
         userToken = win32security.LogonUser(self._user, self._domain,
                                             self._password,
                                             win32con.LOGON32_LOGON_BATCH,
                                             win32con.LOGON32_PROVIDER_DEFAULT)

      except pywintypes.error as e:
         if e.winerror == winerror.ERROR_LOGON_TYPE_NOT_GRANTED:
            log("Retrying with LOGON32_LOGON_SERVICE logon type.")
            try:
               userToken = win32security.LogonUser(self._user, self._domain,
                                                   self._password,
                                                   win32con.LOGON32_LOGON_SERVICE,
                                                   win32con.LOGON32_PROVIDER_DEFAULT)
            except pywintypes.error as ee:
               log("got error %s using service fallback (original error %s)" % (ee, e))
         else:
            log("got error %s during logon attempt (no fallback used)" % e)

      if userToken is None:
         raise WindowsError("Unable to get token for user: %s@%s" %
                            (self._user, self._domain))

      # Start the process
      try:
         procArgs = (executable, # None - appName
                     args,       # commandLine
                     None,       # processAttributes
                     None,       # threadAttributes
                     1,          # bInheritHandles
                     win32process.CREATE_NEW_CONSOLE, # dwCreationFlags
                     env,        # None - newEnvironment
                     cwd,        # None - currentDirectory
                     startupinfo)

         hp, ht, pid, tid = win32process.CreateProcessAsUser(userToken, *procArgs)
      except pywintypes.error as e:
         raise WindowsError(*e.args)

      # Child is launched. Close the parent's copy of those pipe
      # handles that only the child should have open.  You need
      # to make sure that no handles to the write end of the
      # output pipe are maintained in this process or else the
      # pipe will not close when the child process exits and the
      # ReadFile will hang.
      if p2cread is not None or p2cread != -1:
         p2cread.Close()
         if to_close:
            to_close.remove(p2cread)
      if c2pwrite is not None or c2pwrite != -1:
         c2pwrite.Close()
         if to_close:
            to_close.remove(c2pwrite)
      if errwrite is not None or errwrite != -1:
         errwrite.Close()
         if to_close:
            to_close.remove(errwrite)

      # Retain the process handle, but close the thread handle
      self._child_created = True
      self._handle = hp
      self.pid = pid
      ht.Close()


class CisWinSubprocessPy3(CisWinSubprocess):
   """Extends CisWinSubprocess class (which works for python2) to adapt
   the overridden callbacks to python 3. Notable changes:
   - self._handle is expected to be a PyNumber data object by py3 subprocess
     code, but our overridden methods work on PyHANDLE object (converting
     it to python number data type does not seem to work (py3 subprocess
     WaitForSingleObject() call waits indefinitely), so this class adds
     overrides for methods that access self._handle.
   - _execute_child callback args have changed, some args removed, some added.
   """


   def _execute_child(self, args, executable, preexec_fn, close_fds,
                      pass_fds, cwd, env,
                      startupinfo, creationflags, shell,
                      p2cread, p2cwrite,
                      c2pread, c2pwrite,
                      errread, errwrite,
                      unused_restore_signals, unused_start_new_session):
      # Call the parent py2 callback (which expects different args).
      super(CisWinSubprocessPy3, self)._execute_child(
          args, executable, preexec_fn, close_fds,
          # pass_fds ignored, absent in py2
          cwd, env,
          # universal_newlines not passed in py3
          False,  # universal_newlines absent in py3
          startupinfo, creationflags, shell,
          # universal_newlines not passed in py3
          None,
          p2cread, p2cwrite,
          c2pread, c2pwrite,
          errread, errwrite
          # unused_restore_signals ignored,
          # unused_start_new_session ignored, absent
          # in py2
          )


   def wait(self, timeout=None, endtime=None):
      if endtime is not None:
         timeout = self._remaining_time(endtime)
      if timeout is None:
         timeout_millis = win32event.INFINITE
      else:
         timeout_millis = int(timeout * 1000)
      if self.returncode is None:
         result = win32event.WaitForSingleObject(self._handle,
                                                 timeout_millis)
         if result == win32event.WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired(self.args, timeout)
         self.returncode = win32process.GetExitCodeProcess(self._handle)
      return self.returncode


   def _internal_poll(self, _deadstate=None, _WaitForSingleObject=None,
                      _WAIT_OBJECT_0=None, _GetExitCodeProcess=None):
      if _WaitForSingleObject is None:
         _WaitForSingleObject = win32event.WaitForSingleObject
      if _WAIT_OBJECT_0 is None:
         _WAIT_OBJECT_0 = win32event.WAIT_OBJECT_0
      if _GetExitCodeProcess is None:
         _GetExitCodeProcess = win32process.GetExitCodeProcess
      if self.returncode is None:
         if _WaitForSingleObject(self._handle, 0) == _WAIT_OBJECT_0:
            self.returncode = _GetExitCodeProcess(self._handle)
      return self.returncode

   def terminate(self):
      # Don't terminate a process that we know has already died.
      if self.returncode is not None:
         return
      try:
         win32process.TerminateProcess(self._handle, 1)
      except PermissionError:
         # ERROR_ACCESS_DENIED (winerror 5) is received when the
         # process already died.
         rc = win32process.GetExitCodeProcess(self._handle)
         if rc == _winapi.STILL_ACTIVE:
            raise
         self.returncode = rc

   # Hookup kill to overridden terminate
   kill = terminate


def run_as_user(user, domain, password, cmd, stop_on_error, quiet=False):
   """
   execute a command as a given user and return the return code and
   output. if stop_on_error is True it will raise InvokeCommandException
   """
   log("Running command %s as user %s@%s" % (cmd, user, domain), quiet)
   if sys.version_info[0] < 3:
       process = CisWinSubprocess(user, domain, password, cmd,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
   else:
       process = CisWinSubprocessPy3(user, domain, password, cmd,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
   stdout, stderr = process.communicate()
   rc = process.returncode
   stdout = stdout if stdout else ''
   stderr = stderr if stderr else ''

   if sys.version_info[0] >= 3 and isinstance(stdout, bytes):
      stdout = toUnicode(stdout)
   if sys.version_info[0] >= 3 and isinstance(stderr, bytes):
      stderr = toUnicode(stderr)

   stdout = stdout.strip()
   stderr = stderr.strip()

   if rc != 0 and stop_on_error:
      errMsg = _T('install.ciscommon.run_as_user',
                  'Failed running command %s as user %s@%s.\n'
                  'Return Value: %d, Stdout: %s, Stderr: %s')
      loErrMsg = localizedString(errMsg, [cmd, user, domain, rc,\
                                 stdout, stderr])
      log_error('Failed running %s as user %s@%s. RC: %d, Stdout: %s, Stderr: %s' %
                (cmd, user, domain, rc, stdout, stderr))
      raise BaseInstallException(ErrorInfo([loErrMsg]))

   return rc, stdout, stderr

def quote(val):
   """
   wrap a value with quotes
   """
   return '"' + val + '"'

def to_unix_path(file_path):
   """
   Converts the provided path to a unix-style one
   """
   return os.path.normpath(file_path).replace('\\', '/')

def get_deployment_size(cpuCount=0, memory=0, hostCount=0, vmCount=0,
                        disksCount={}):
    """
    Get the deployment size based on given constraints.

    In case the given constraints satisfy more than one deployment size,
    the smallest one is returned.
    If the constraints do not satisfy any of the sizes, the largest one
    is returned.
    """
    # OVF deployment size profiles file
    UPGRADE_DIR = os.path.join(get_cis_install_dir(), 'vmware',
                               'cis_upgrade_runner')
    DEPLOYMENT_SIZE_LAYOUT_FILE = os.path.join(UPGRADE_DIR, 'config',
                                               'deployment-size-layout.json')

    # OVF deployment size profile ordering
    DEPLOYMENT_SIZE_ORDERING = ["tiny", "small", "medium", "large", "xlarge"]

    try:
        with open(DEPLOYMENT_SIZE_LAYOUT_FILE) as f:
            sizes = json.loads(f.read())
    except Exception as e:
        log_error("Failed to load '%s' file; Error: %s"
                  % (DEPLOYMENT_SIZE_LAYOUT_FILE, str(e)))
        return None

    constraintDict = {
        "cpu": cpuCount,
        "memory": memory,
        "host-count": hostCount,
        "vm-count": vmCount,
        "disk-core": disksCount.get('core', 0),
        "disk-log": disksCount.get('log', 0),
        "disk-db": disksCount.get('db', 0),
        "disk-dblog": disksCount.get('dblog', 0),
        "disk-seat": disksCount.get('seat', 0),
        "disk-netdump": disksCount.get('netdump', 0),
        "disk-autodeploy": disksCount.get('autodeploy', 0),
        "disk-imagebuilder": disksCount.get('imagebuilder', 0),
        "disk-updatemgr": disksCount.get('updatemgr', 0),
        "disk-archive": disksCount.get('archive', 0)
    }

    # Assign the deployment size to the largest one, this is the default.
    # Check each size in order and take the first that satisfies
    # all the constraints.
    deploymentSize = DEPLOYMENT_SIZE_ORDERING[-1]
    for size in DEPLOYMENT_SIZE_ORDERING:
        if all(float(re.sub("GB", "", str(sizes[size][k]))) >= v
            for k, v in constraintDict.items()):
            deploymentSize = size
            break
    return deploymentSize

def get_deployment_nodetype():
   """
   Get current system deployment node type.
   This file is created during run-firstboot-scripts.
   """
   fPath = os.path.join(get_cis_config_dir(), 'deployment.node.type')
   with codecs.open(fPath, 'r', 'utf-8') as fp:
       return fp.read().strip()

def set_deployment_nodetype(node_type):
   '''
   Replace the current deployment.node.type with new value.
   This is required when converting an embeded node to management node.
   '''
   fPath = os.path.join(get_cis_config_dir(), 'deployment.node.type')
   try:
      with codecs.open(fPath, 'w', 'utf-8') as fp:
         fp.write(node_type)
         return True
   except Exception as e:
      err_msg = "Failed to change deployment.node.type to %s" % (node_type)
      logging.error("%s Error: %s" %(err_msg, e))
      return False

def get_db_type():
   '''
   Get whether current VC database is embedded or external.
   This file is created during run-firstboot-scripts.
   '''
   fPath = os.path.join(get_cis_config_dir(), 'db.type')
   with codecs.open(fPath, 'r', 'utf-8') as fp:
      return fp.read().strip()

def systemd_disable_service(svc_name):
    '''
    Set systemd service to masked state. Systemd won't start the masked
    service even if there is some which has put a Required-Start deps on it.
    '''
    if osIsSystemd:
        cmd = [_systemctl_path, 'mask', '%s.service' % svc_name]
        rc, stdour, stderr = run_command(cmd)
        if rc != 0:
            log_warning('Unable to mask service %s. Error %s' %
                        (stderr, svc_name))
            return False
        return True
    return False

def enable_svc_cgroup_accounting(svc_name, quiet=False):
    '''
    Give a service name enabled cgroup accounting for the service.
    This is applicable only on sles12.
    '''
    cmd = [_systemctl_path, 'set-property',
           '%s.service' % svc_name, 'MemoryAccounting=true',
           'CPUAccounting=true', 'BlockIOAccounting=true']
    rc, stdout, stderr = run_command(cmd, quiet=quiet)
    if rc != 0:
        log_warning('Failure setting accounting for %s. Err %s' %
                    (svc_name, stderr), quiet=quiet)

#
# Security related functions
#
def gen_random_pwd(length=16):
   """
   returns a random password conforming to VMware security policy.
   For more info refer to -
   http://security.eng.vmware.com/PSP/requirements.html#__RefHeading__2319_1756061063

   It make sure there is at least one character from each character sets defined
   below. It ensure password does not have repeated or consecutive identical
   characters.
   """
   SMALL    = list(string.ascii_letters[0:26])
   CAPS     = list(string.ascii_letters[26:52])
   NUM      = list(string.digits)
   # Note: The special characters : \ ' - are omitted for jdbcUrl escape issues,
   SPECIAL  = list(r'!@#$%^&*()_+{}|<>?=')
   BUCKETS = [SMALL, CAPS, NUM, SPECIAL]
   alphabet = SMALL + CAPS + NUM + SPECIAL
   MIN_LEN = 8
   if length < MIN_LEN:
      raise SecurityException("Password length is smaller than minimum "
                              "password length of " + str(MIN_LEN) +
                              " characters")
   if length > len(alphabet):
      raise Exception("Requested password length exceeds alphabet size ("
                      + str(len(alphabet)) + ")")
   rand = random.SystemRandom()
   pwd = [None] * length
   idx = list(range(length))
   # Choose a character from each bucket and sprinkle at random places
   mandatory_chars = [rand.choice(b) for b in BUCKETS]
   for i in range(len(BUCKETS)):
      pos = idx.pop(rand.randrange(len(idx)))
      pwd[pos] = mandatory_chars.pop()
      # To avoid consecutive, identical chars, remove the previous pwd
      # char from the alphabet
      alphabet.remove(pwd[pos])

   # Fill in rest of the chars
   for i in idx:
      pwd[i] = rand.choice(alphabet)
      alphabet.remove(pwd[i])

   return ''.join(pwd)

# Need to be removed while fixing PR#1746540
def is_svc_vmon_integrated(svc_name):
    from cis.svcsController import SvcsInfoMgr
    svcInfoMgr = SvcsInfoMgr()
    try:
        svc_node_name = svcInfoMgr.get_svc_nodename(svc_name)
        if svcInfoMgr.is_vmon_svc(svc_node_name):
            return True
        else:
            return False
    except ServiceNotFoundException:
        # log_warning("Unable to find service %s" % svc_name)
        return False

def _vmon_service_stop_helper(svc_name, quiet=False):
    '''
    Helper function which attempts to stop given service by talking to vMon.
    Return:
        True if service was successfully stopped via vMon.
        False if service was not registered with vMon.

    Raises ServiceStopException exception in case of error.
    '''
    cis_vmon =  CISVmonServiceControl(svc_name)
    rc, stdout, stderr = cis_vmon.stop_service()
    if rc == vMonError.VMON_ERRNO_SUCCESS:
        log('Successfully stopped %s service' % svc_name, quiet)
        return True
    elif rc == vMonError.VMON_ERRNO_VMON_UNAVAILABLE:
        log('Service vMon is not running. Service %s already in "STOPPED" '
            'state.' % svc_name)
        return True
    elif rc != vMonError.VMON_ERRNO_INVALID_INPUT:
        log_error('ERROR stopping %s rc: %d, stdout: %s, stderr: %s'
                  % (svc_name, rc, stdout, stderr), quiet)
    else:
        log_error('Failed to stop service %s due to invalid input.' % svc_name)
    raise ServiceStopException(svc_name)

#
# Service control functions
#
def service_stop(svc_name, wait_time=300, quiet=False, force_kill=True,
                 check_state=False):
   '''
   Will throw ServiceStopException if service failes to stop.
   '''
   if  check_state:
      (ret, state) = service_query_status(svc_name, quiet=quiet)
      if state ==  'STOPPED':
         return 0

   svc_stopped = True

   if is_svc_vmon_integrated(svc_name) and _vmon_service_stop_helper(svc_name, quiet):
      return 0

   stopFunc = def_by_os(service_stop_lin, service_stop_win)
   svc_stopped = stopFunc(svc_name, wait_time, quiet, force_kill, check_state)

   if not svc_stopped:
      log_error("Service %s could not be stopped correctly" % svc_name, quiet)
      raise ServiceStopException(svc_name)

   log("Successfully stopped service %s" % svc_name, quiet)

   # XXX We actually don't need to return anything. But since we did earlier and
   # vmidentity-firstboot uses it, return 0.
   return 0


def service_stop_lin(svc_name, wait_time=300, quiet=False, force_kill=True,
                     check_state=False):
   '''
   Stop a service.
   '''
   if os.name != 'posix':
      return

   svc_stopped = True
   cmd = [get_svc_cmd(), svc_name, "stop"]
   rc, stdout, stderr = run_command(cmd, quiet=quiet)
   if rc != 0:
      log_error('ERROR stopping %s rc: %s, stdout: %s, stderr: %s'
                % (svc_name, rc, stdout, stderr), quiet)
      svc_stopped = False
   return svc_stopped


def service_stop_win(svc_name, wait_time=300, quiet=False, force_kill=True,
                     check_state=False):
   '''
   Stop a windows service registered with SCM.
   '''
   if os.name == 'posix':
      return

   svc_stopped = True
   try:
      cis_win_scm = CISWinServiceControl(svc_name)
      cis_win_scm.open()
      cis_win_scm.service_stop()
      svc_stopped = wait_for_state(svc_name, "STOPPED", wait_time, quiet) == 0
   except pywintypes.error as e:
      if e.winerror == winerror.ERROR_SERVICE_NOT_ACTIVE:
         log('Service: %s is already stopped.' % svc_name)
      elif e.winerror == winerror.ERROR_SERVICE_DOES_NOT_EXIST:
         log('Service: %s does not exist.' % svc_name)
      else:
         log_error('ERROR stopping service: %s, Exception: %s' % (svc_name, e))
         svc_stopped = False
   finally:
      if force_kill and not svc_stopped:
         log("Forcing kill of service %s" % svc_name, quiet)
         # Disable recovery actions of the service before killing.
         orig_fail_actions = cis_win_scm.get_svc_failure_actions()
         cis_win_scm.disable_recovery_actions()
         # Log watchdog configuration after it has been disabled
         fail_actions = cis_win_scm.get_svc_failure_actions()
         log("Failure actions for service after disabling recovery: %s"
             % fail_actions)
         cis_win_scm.kill_service()
         # Check service state before enabling watchdog
         (ret, state) = service_query_status(svc_name, quiet=quiet)
         log("Before enabling watchdog %s is in %s state" %(svc_name, state))
         if state == "STOPPED":
            svc_stopped = True
         # Enable the service recovery actions.
         cis_win_scm.set_svc_failure_actions(orig_fail_actions)
      cis_win_scm.close()
   return svc_stopped


def service_start(svc_name, wait_time=1800, quiet=False, manual_start=False,
                  check_state=False):
   '''
   For any service integrated with vMon, we try to start service via vMon.
   If we detect that vMon is not running or if vMon doesn't know anything about
   the service, we raise an exception. For all other services, we use
   OS based(service/windows SCM) service start.

   Will throw ServiceStartException if service fails to start.
   '''
   #If service is running skip starting the service
   if  check_state:
      (ret, state) = service_query_status(svc_name, quiet=quiet)
      if state == "RUNNING":
         return 0

   if is_svc_vmon_integrated(svc_name):
      cis_vmon =  CISVmonServiceControl(svc_name)
      rc, stdout, stderr =  cis_vmon.start_service()
      if rc == vMonError.VMON_ERRNO_SUCCESS:
          log('Successfully started %s service' % svc_name, quiet)
          return rc
      elif rc == vMonError.VMON_ERRNO_VMON_UNAVAILABLE:
          log_warning('Service vMon is not running. Failed in starting service '
                      '%s.' % svc_name)
      elif rc != vMonError.VMON_ERRNO_INVALID_INPUT:
          log_error('ERROR starting %s rc: %s, stdout: %s, stderr: %s'
                     % (svc_name, rc, stdout, stderr), quiet)
      else:
          log_error('Invalid input received in start request. Service %s.'
                    % svc_name)
      raise ServiceStartException(svc_name)
   else:
      service_started = True
      if os.name == 'posix':
         try:
            invoke_command([_systemctl_path, 'daemon-reload'], quiet=quiet)
            # Unfortunately this doesn't work for all services. Systemctl
            # complains that the service is not loaded.
            enable_svc_cgroup_accounting(svc_name, quiet=quiet)

            if not manual_start:
               invoke_command([_systemctl_path, 'enable', svc_name],
                              quiet=quiet)

            cmd = [get_svc_cmd(), svc_name, "start"]
            invoke_command(cmd, quiet=quiet, close_fds=True)
         except InvokeCommandException as e:
            log_error(e)
            service_started = False
      else:
         try:
            # Start a windows service.
            cis_win_scm = CISWinServiceControl(svc_name)
            cis_win_scm.open()
            service_started =\
               cis_win_scm.service_start(max_wait_time=wait_time) == 0
         except pywintypes.error as e:
            log_error('ERROR Starting service: %s, Exception: %s' %
                      (svc_name, e))
            service_started = False
         finally:
            cis_win_scm.close()

      if not service_started:
         raise ServiceStartException(svc_name)

   log("Successfully started service %s" % svc_name, quiet)

   # XXX We actually don't need to return anything. But since we did earlier and
   # vmidentity-firstboot uses it return 0.
   return 0


def _service_query_status_internal(svc_name, quiet=False):
   '''
   For any service integrated with vMon, we query status of service via vMon.
   If we detect that vMon is not running, we declare the service as STOPPED.
   If vMon doesn't know anything about the service, we declare the state
   'UNKNOWN'. For all other services, we use OS based(service/windows SCM)
   service status.
   '''
   ret = 0
   state = "UNKNOWN"
   isFailStop = False

   if is_svc_vmon_integrated(svc_name):
      cis_vmon =  CISVmonServiceControl(svc_name)
      rc, state, isFailStop, stdout, stderr = cis_vmon.get_service_state()
      if rc == vMonError.VMON_ERRNO_SUCCESS:
         log('Service %s state %s' % (svc_name, state), quiet)
         if state == "STARTED":
            state = "RUNNING"
         elif state == "STARTING":
            state = "START_PENDING"
         elif state == "STOPPING":
            state = "STOP_PENDING"
         else:
            state = "STOPPED"
      elif rc == vMonError.VMON_ERRNO_VMON_UNAVAILABLE:
         log_warning('Warning: service vMon is not running. State of service '
                     '%s is STOPPED.' % svc_name)
         state = 'STOPPED'
         isFailStop = False
      elif rc != vMonError.VMON_ERRNO_INVALID_INPUT:
         ret = 1
         log_error('Error: state of svc: %s rc : %s, stdout: %s, stderr: %s'
                   % (svc_name, rc, stdout, stderr))
      else:
        ret = 1
        log_error('Error: Service name "%s" is invalid.' % svc_name)

      return (ret, state, isFailStop)

   if os.name == 'posix':
      cmd = [get_svc_cmd(), svc_name, "status"]
      rc, stdout, stderr = run_command(cmd, quiet=quiet)
      if rc != 0:
         ret = 1
         state = "STOPPED"
      else:
         state = "RUNNING"
   else:
      # query a windows service
      try:
         # QueryServiceStatus returns tuple.
         # (svcType,svcState,ctrlsAccepted,exitCode,errCode,chkPoint,waitHint)
         status = win32serviceutil.QueryServiceStatus(svc_name)[1]
         if status == win32service.SERVICE_RUNNING:
            state = "RUNNING"
         elif status == win32service.SERVICE_STOPPED:
            state = "STOPPED"
         elif status == win32service.SERVICE_START_PENDING:
            state = "START_PENDING"
         elif status == win32service.SERVICE_STOP_PENDING:
            state = "STOP_PENDING"
         elif status == win32service.SERVICE_PAUSED:
            state = "PAUSED"
         elif status == win32service.SERVICE_PAUSE_PENDING:
            state = "PAUSED_PENDING"
         elif status == win32service.SERVICE_CONTINUE_PENDING:
            state = "SERVICE_CONTINUE_PENDING"
         else:
            raise Exception("Unknown status %s for service %s." %
                            (status, svc_name))
      except pywintypes.error as e:
         ret = 1
         log_error("ERROR unable to query service %s, %s" % (svc_name, e))
      log("State for service %s: %s" % (svc_name, state), quiet)

   return (ret, state, isFailStop)


def service_query_status(svc_name, quiet=False):
   ret, state, _ = _service_query_status_internal(svc_name, quiet)
   return (ret, state)


def service_query_status_ex(svc_name, quiet=False):
   ret, state, isFailStop = _service_query_status_internal(svc_name, quiet)
   return (ret, state, isFailStop)


def service_uninstall(svc_name):
   if is_svc_vmon_integrated(svc_name) and _vmon_service_stop_helper(svc_name):
      return  # SUCCESS

   if os.name == 'posix':
      raise NotImplementedException("service_uninstall not implemented for posix")
   else:
      service_stop(svc_name)

      try:
         log("Removing service from Service Control Manager")
         win32serviceutil.RemoveService(svc_name)
      except pywintypes.error as e:
         if e.winerror == winerror.ERROR_SERVICE_DOES_NOT_EXIST:
            log_warning("Service %s does not exists. Nothing to uninstall." % svc_name)
         else:
            log_error("Error removing service: %s, Exception %s" % (svc_name, e))
            raise ServiceUninstallException(svc_name)

def service_update(svc_name, prop_name, prop_value, quiet=False):
   """
   update service start type for service
   * svc_name - str, name of the service
   * start_type - DISABLED, MANUAL or AUTOMATIC
   * TODO: Will define vMonException class later
   * to implement proper error handling.
   """
   if is_svc_vmon_integrated(svc_name):
      cis_vmon =  CISVmonServiceControl(svc_name)
      if prop_name == 'starttype':
          rc, stdout, stderr =  cis_vmon.update_service_starttype(prop_value)
          if rc == vMonError.VMON_ERRNO_SUCCESS:
              log('Successfully updated starttype: %s for service %s' %
                  (prop_value, svc_name), quiet)
              return rc
          elif rc == vMonError.VMON_ERRNO_VMON_UNAVAILABLE:
              log_warning('Service vMon is not running. Failed to udpate '
                          '%s to %s for service %s.' %
                          (prop_name, prop_value, svc_name))
          elif rc != vMonError.VMON_ERRNO_INVALID_INPUT:
              log_error('ERROR updating %s %s to %s.'
                         % (svc_name, prop_name, prop_value), quiet)
          else:
              log_error('Failed to update %s to %s of service due to '
                        'invalid input. svc: %s  stdout: %s, stderr: %s' %
                        (prop_name, prop_value, svc_name, stdout, stderr),
                        quiet)
          raise Exception('Error: updating svc: %s rc : %s, stdout: %s, '
                          'stderr: %s' % (svc_name, rc, stdout, stderr))
   else:
      log('service_update is for updating only vMon integrated svc properties')
      raise Exception('service_update is for updating only vMon integrated svc '
                      'properties')

def set_service_start_type(svc_name, start_type, quiet=False):
   """
   Sets start type for service
    * svc_name - str, name of the service
    * start_type - str, one of StartType.DISABLED, StartType.MANUAL or
         StartType.AUTO
    * if service is integrated with vmon, vMon_start_type will map
      the service starttype as needed
   May raise ServiceNotFoundException or SetServiceStartTypeException
   """

   assert start_type in (StartType.DISABLED, StartType.MANUAL, StartType.AUTO)

   # if svc is integrated with vMon
   if is_svc_vmon_integrated(svc_name):
      cis_vmon =  CISVmonServiceControl(svc_name)
      prop_name = 'starttype'
      prop_value = cis_vmon.vMon_start_type(start_type)
      try:
          rc = service_update(svc_name, prop_name, prop_value)
          if rc == vMonError.VMON_ERRNO_SUCCESS:
              log('Successfully updated %s service' % svc_name, quiet)
              return
      except Exception as e:
          log_error('ERROR in setting starttype %s %s'
                   % (prop_value, e), quiet)
          raise SetServiceStartTypeException(svc_name)

   if os.name == 'posix':
      # On systemd systems following is the start type contract
      # AUTOMATIC = enabled
      # MANUAL = disabled
      # DISABLED = masked
      if start_type == StartType.AUTO:
         rc, stdout, stderr = run_command(
             [_systemctl_path, 'unmask', svc_name], quiet=quiet)
         if rc == 0:
             rc, stdout, stderr = run_command(
                 [_systemctl_path, 'enable', svc_name], quiet=quiet)
      elif start_type == StartType.MANUAL:
         rc, stdout, stderr = run_command(
             [_systemctl_path, 'unmask', svc_name], quiet=quiet)
         if rc == 0:
             rc, stdout, stderr = run_command(
                 [_systemctl_path, 'disable', svc_name], quiet=quiet)
      else:
          rc, stdout, stderr = run_command(
             [_systemctl_path, 'mask', svc_name], quiet=quiet)

      if rc != 0:
         log_error('ERROR setting start type %s for service: %s, stderr: %s'
                   % (start_type, svc_name, stderr))
         if ('unknown service' in stderr or
             'No such file' in stderr):
            raise ServiceNotFoundException(svc_name)
         raise SetServiceStartTypeException(svc_name)
   else:
      # setting start type on Windows
      try:
         cis_win_scm = CISWinServiceControl(svc_name)
         cis_win_scm.open()
         cis_win_scm.set_start_type(StartType.WIN32[start_type])
      except pywintypes.error as e:
         log_error('ERROR setting start type %s for service: %s, '
                   'Exception: %s' % (start_type, svc_name, e))
         if e.winerror == 1060:
            # 1060 stands for "The specified service does not exist as an
            # installed service"
            raise ServiceNotFoundException(svc_name)
         raise SetServiceStartTypeException(svc_name)
      finally:
         cis_win_scm.close()

def wait_for_state(svc_name, svc_state, wait_time=300, quiet=False):
   ret = 0
   waitCnt = wait_time/10
   cnt = 0
   while cnt < waitCnt:
      (ret, state) = service_query_status(svc_name, quiet=quiet)
      state = state.rstrip()
      if state == svc_state:
         break
      cnt = cnt + 1
      sleep_uninterruptible(10)

   if cnt == waitCnt:
      ret = 1

   return ret

def wait_for_svc(svc_name, wait_time=300, quiet=False):
   log("Waiting for %s to start..." % svc_name, quiet)
   ret = wait_for_state(svc_name, "RUNNING", wait_time, quiet)
   if ret:
      log_warning("Timed out waiting for service %s..." % svc_name, quiet)
   return ret

def get_ssl_trust(sslCertContent):
   """
   Helper method which strips Begin and End certificate tags from PEM formatted
   certificate and returns rest of the contents.
   """
   m = re.search('^-----BEGIN CERTIFICATE-----$(.*)^-----END CERTIFICATE-----$',
                 sslCertContent,
                 re.MULTILINE | re.DOTALL)
   if not m:
      raise Exception('Could not extract certificate.')
   return m.group(1).replace('\n', '')

def read_ssl_certificate(cert_path):
   """
   Helper method to read a PEM format SSL cert file.
   """
   with codecs.open(cert_path, 'r', 'utf-8') as f:
      content = f.read()
   return get_ssl_trust(content)

#
# File manipulation functions
#
def readprop(file_name, name):
   """
   read a property
   """
   with codecs.open(file_name, 'r', 'utf-8') as f:
      propline = ''
      for line in f:
         propline += line
         if len(propline) < 2 or not propline.endswith("\\\n"):
            if re.search('^[^#!]', propline):
               s = propline.find('=')
               if s >= 1:
                  key = propline[:s].strip()
                  value = propline[s + 1:].strip()
                  if key == name:
                     return value
            propline = ''


def read_properties(file_name, prop_keys=None):
   """
   read set of property keys and return a map of key-value
   """
   kvStore = dict()
   with codecs.open(file_name, 'r', 'utf-8') as f:
      for line in f:
         if re.search('^[^#!]', line):
            s = line.find('=')
            if s >= 1:
               key = line[:s].strip()
               value = line[s + 1:].strip()
               if prop_keys == None or key in prop_keys:
                  kvStore[key] = value
   return kvStore

def remove_file(file_name):
   """
   Remove the specified file. Ignore any exceptions
   """
   try:
      os.remove(file_name)
   except:
      pass

def write_props_to_file(file_name, props, mode='w'):
   """
   Write properties to a specified file. Default mode will create
   a new file and overwrite if file exists.
   """
   with codecs.open(file_name, mode, 'utf-8') as f:
      for prop in props:
         value = prop[1]
         # Python 3 hack, string has no decode() function.
         if sys.version_info < (3,0,0) and isinstance(prop[1], str):
            value = prop[1].decode('utf-8')
         f.write('%s = %s\n' % (prop[0], value))

def replace_properties_in_file(file_name, args, quiet=False):
   """
   Replaces properties in "java-style" properties file
   """

   log("Replacing properties in %s" % file_name, quiet)

   f = FileBuffer()
   try:
      f.readFile(file_name)

      for k, v in args.items():
         f.updateKeyValue(k, v)

      f.writeFile(file_name)
   finally:
      f.clearBuffer()

def text_subst_in_file(file_name, text_subst_args, quiet=False):
   """
   Performs text substitutions by applying replacements specified in
   the provided text_subst_args
   """

   log("Performing text substitutions in %s" % file_name, quiet)

   f = FileBuffer()
   try:
      f.readFile(file_name)

      for k, v in text_subst_args.items():
         f.findAndReplace(k, v)

      f.writeFile(file_name)
   finally:
      f.clearBuffer()

def parse_json_string(string, type=None, description=""):
   """
   Parse the provided string into an object of the specified type.

   The provided description (e.g., "in file '/foo/bar.json'" or
   "in install parameter 'foo.bar'") is used to log problems parsing
   the string, naming the origin of the string.
   """
   try:
      object = json.loads(string)
      if type and not isinstance(object, type):
         raise ValueError("Data is not of type %s: %s" %
                          (type.__name__, string.rstrip()))
   except ValueError as e:
      log_error("Malformed data%s: %s" % (description, e))
      raise
   return object

def load_json(path, type=None, ignore_io_errors=True):
   """
   Load and return the object of the provided type encoded in the specified
   json file.

   If ignore_io_errors and the the file can't be opened, an object of the
   provided type is return (i.e., type()).
   """
   object = None
   if type:
      object = type()
   try:
      with codecs.open(path, "r", 'utf-8') as f:
         object = parse_json_string(f.read(), type, " in file '%s'" % path)
   except (IOError,ValueError) as e:
      log("Missing, unreadable, or malformed file (%s): %s" % (path, e))
      if not ignore_io_errors or not isinstance(e, IOError):
         raise
   return object

def escapePropertyValue(value):
   if isinstance(value, str) or isinstance(value, unicode):
      return value.replace('\\', '\\\\')
   return value


class CISVmonServiceControl(object):
   """
   Implements a class that provides an interface to interact
   with the Vmon Service Daemon using vmon-cli.
   TODO: will define vMonException class and change the return
   type more generic than current cli specific implementation.
   """

   def __init__(self, svc_name):
      self._svc_name = svc_name
      self._cli = get_vmon_cli_path()

   def __enter__(self):
      return self

   def _get_service_status(self):
      rc, stdout, stderr = self.execute_vmon_cmd('status')
      if rc == vMonError.VMON_ERRNO_SUCCESS:
          stdout = stdout.strip()
          stdout = dict([(k.strip(),v.strip()) for k,v in [e.split(':')
                    for e in stdout.split('\n')]])

      return rc, stdout, stderr

   def get_service_state(self):
       state = 'UNKNOWN'
       isFailStop = False
       rc, stdout, stderr = self._get_service_status()
       if rc == vMonError.VMON_ERRNO_SUCCESS:
           state = stdout['RunState']
           isFailStop = True if stdout['FailStop'] == "TRUE" else False
       return rc, state, isFailStop, stdout, stderr

   def execute_vmon_cmd(self, action, option=None):
       actopt = '--%s' % action
       cmd = [self._cli, actopt, self._svc_name]
       return run_command(cmd, quiet=True)

   def get_service_start_type(self):
       startType = 'UNKNOWN'
       rc, stdout, stderr = self._get_service_status()
       if rc == vMonError.VMON_ERRNO_SUCCESS:
           startType = stdout['Starttype']
       return rc, startType, stdout, stderr

   def vMon_start_type(self, start_type):
      startType ='Disabled:DISABLED,Manual:MANUAL,Automatic:AUTOMATIC'
      startType = dict([(k,v) for k,v in [e.split(':')
                        for e in startType.split(',')]])
      return startType[start_type]

   def get_service_health(self):
       health = 'UNKNOWN'
       rc, stdout, stderr = self._get_service_status()
       if rc == vMonError.VMON_ERRNO_SUCCESS:
           health = stdout['HealthState']
       return rc, health, stdout, stderr

   def get_service_list(self):
       return self.execute_vmon_cmd('list')

   def stop_service(self):
       return self.execute_vmon_cmd('stop')

   def start_service(self):
       return self.execute_vmon_cmd('start')

   def _update_service_prop(self, svc_prop):
       action = '--update'
       cmd =  [self._cli, action, self._svc_name]
       if svc_prop['Name'] == 'starttype':
          cmd.append('-S')
       elif svc_prop['Name'] == 'runasuser':
          cmd.append('-R')
       cmd.append(svc_prop['Value'])
       return run_command(cmd, quiet=True)

   def update_service_starttype(self, start_type):
       svc_prop = {}
       svc_prop['Name'] = 'starttype'
       svc_prop['Value'] = start_type
       return self._update_service_prop(svc_prop)

   def set_run_as_user(self, user_name):
       svc_prop = {}
       svc_prop['Name'] = 'runasuser'
       svc_prop['Value'] = user_name
       return self._update_service_prop(svc_prop)

class CISWinServiceControl(object):
   """
   Implements a class that provides an interface to interact
   with the Windows Service Control Manager.
   Throws pywintypes.error exception
   """
   def __init__(self, svc_name):
      self._svc_name = svc_name
      self.__reset_svchandles()

   def __enter__(self):
      return self

   def open(self):
      '''
      Open scm and service handles.
      '''
      self._scm = win32service.OpenSCManager(None,
                                             None,
                                             win32service.SC_MANAGER_ALL_ACCESS)
      self._svc_handle = win32service.OpenService(self._scm, self._svc_name,
         win32service.SERVICE_ALL_ACCESS)

   def __reset_svchandles(self):
      self._scm = None
      self._svc_handle = None

   def get_service_status(self):
      '''
      Returns a dictionary with following keys
      ControlsAccepted, ServiceType, WaitHint, ServiceSpecificExitCode,
      ProcessId, ServiceFlags, CheckPoint, Win32ExitCode, CurrentState
      '''
      return win32service.QueryServiceStatusEx(self._svc_handle)

   def get_service_pid(self):
      return self.get_service_status()['ProcessId']

   def get_service_state(self):
      return self.get_service_status()['CurrentState']

   def service_stop(self):
      win32service.ControlService(self._svc_handle, win32service.SERVICE_CONTROL_STOP)

   def enable_delayed_recovery_actions(self, resetActionSec=0,
                                       firstRestartDelay=180,
                                       secondRestartDelay=180,
                                       rebootFlag=False):
      '''
      Enables 'restart' SCM recovery actions with default 180s delay
      for this service.
      Note: We do not want to enable a crashed process immediately.
      For Java services, SCM monitors the wrapper crashes, and our
      defaults here are set to match those in wrapper_windows.conf.
      For the sake of uniformity, we extend the same to C++ services.
      '''
      if rebootFlag:
         '''
         Setup reboot action and have it reboot after a 5 minute delay to
         allow for customers to cancel the reboot action.  This is especially
         needed to deal with a reboot loop scenario, which SCM can fall into.
         '''
         actions = [(win32service.SC_ACTION_RESTART, firstRestartDelay*1000),
                    (win32service.SC_ACTION_RESTART, secondRestartDelay*1000),
                    (win32service.SC_ACTION_REBOOT, 300*1000)]
         rebootMsg = ('vCenter Server is rebooting due to repeated service'
                     ' failures, if system does not recover following'
                     ' reboot, please contact VMware support.')
      else:
         actions = [(win32service.SC_ACTION_RESTART, firstRestartDelay*1000),
                    (win32service.SC_ACTION_RESTART, secondRestartDelay*1000),
                    (win32service.SC_ACTION_NONE, 0)]
         rebootMsg = ""
      fail_actions = {
            'ResetPeriod': resetActionSec,
            'RebootMsg': rebootMsg,
            'Command': '',
            'Actions': actions
      }

      self.set_svc_failure_actions(fail_actions)

   def disable_recovery_actions(self):
      '''
      Disables SCM recovery actions for this service.
      '''
      fail_actions = {
         'ResetPeriod': 0,
         'RebootMsg': '',
         'Command': '',
         'Actions': [(win32service.SC_ACTION_NONE, 0),
                     (win32service.SC_ACTION_NONE, 0),
                     (win32service.SC_ACTION_NONE, 0)]}
      self.set_svc_failure_actions(fail_actions)

   def get_svc_failure_actions(self):
      return win32service.QueryServiceConfig2(self._svc_handle,
         win32service.SERVICE_CONFIG_FAILURE_ACTIONS)

   def set_svc_failure_actions(self, fail_actions):
      '''
      fail_actions should be a  SERVICE_FAILURE_ACTIONS dict.
      Change privilege so we can register reboot as an action following
      service failure.
      '''
      change_privilege(win32con.SE_SHUTDOWN_NAME)
      win32service.ChangeServiceConfig2(self._svc_handle,
        win32service.SERVICE_CONFIG_FAILURE_ACTIONS, fail_actions)

   def wait_for_svc_start(self, max_wait_time=1800):
      '''
      Waits for a service which has been initiated to reach running state.
      Basically polls scm for service state till one of the following is True
      1> Service is no longer in START_PENDING state
      2> max_wait_time has been spent polling.

      NOTE:-Should be called only after StartService is issued to a service.

      Returns:
         0 - If service transitions to RUNNING state.
         1 - If max_wait_time is reached waiting for service to transition
             out of START_PENDING state
         2 - If service transitioned to a state other than the RUNNING state.
      '''
      svc_status = self.get_service_status()

      total_sleep_duration = 0
      while svc_status['CurrentState'] == win32service.SERVICE_START_PENDING:
         if total_sleep_duration >= max_wait_time:
            break
         # According to MSDN, a good wait interval is one-tenth the wait hint,
         # but no less than 1 second and no more than 10 seconds.
         sleep_duration = min(max(1, svc_status['WaitHint']/10000), 10)
         sleep_uninterruptible(sleep_duration)
         total_sleep_duration = total_sleep_duration + sleep_duration
         svc_status = self.get_service_status()

      if svc_status['CurrentState'] == win32service.SERVICE_RUNNING:
         return 0
      elif total_sleep_duration >= max_wait_time:
         log_error('Timed out waiting for service %s start' % self._svc_name)
         return 1
      else:
         log_error('Error waiting for service %s start. Exit code: %d Current State: %d'
                   % (self._svc_name, svc_status['Win32ExitCode'],
                      svc_status['CurrentState']))
         return 2

   def service_start(self, wait_for_service=True, max_wait_time=1800,
                     start_args=None):
      '''
      Start windows service. If wait_for_service is True, we will wait for
      service to go to RUNNING state.
      If wait_for_service if False just returns 0, else refer method
      wait_for_svc_start for return value.
      '''
      if self.get_service_state() == win32service.SERVICE_RUNNING:
         return 0

      win32service.StartService(self._svc_handle, start_args)
      if wait_for_service:
         return self.wait_for_svc_start(max_wait_time)
      return 0

   def kill_service(self):
      try:
         pid = self.get_service_pid()
         if pid == 0:
            log('No process for service: %s'  % self._svc_name)
            return
         else:
            log('Killing process: %d, service: %s' % (pid, self._svc_name))
            cmd = "taskkill /F /T /PID %d" % pid
            invoke_command(cmd)
            # wait 300 sec to make sure service reached stopped state
            # Currently JVM waits for 2 min when wrapper is suddenly stopped and
            # JVM usually takes less than a minute to stop
            wait_for_state(self._svc_name, "STOPPED")
      except (pywintypes.error, InvokeCommandException) as e:
         log_warning('Exception while trying to kill process: %d. Error %s' % (pid, e))

   def change_service_account(self, accnt, accnt_pwd):
       # Python 3 hack, string has no decode() function.
      if sys.version_info < (3,0,0) and isinstance(accnt, str):
          accnt = accnt.decode('utf-8')
      if sys.version_info < (3,0,0) and isinstance(accnt_pwd, str):
          accnt_pwd = accnt_pwd.decode('utf-8')
      win32service.ChangeServiceConfig(self._svc_handle, # handle of service
                                       win32service.SERVICE_NO_CHANGE,  # svc type
                                       win32service.SERVICE_NO_CHANGE,  # svc start type
                                       win32service.SERVICE_NO_CHANGE,  # error control
                                       None, # binary path
                                       None, # load order group
                                       0, # tag ID
                                       None, # dependencies
                                       accnt,   # account name
                                       accnt_pwd,  # account password
                                       None) # display name

   def set_start_type(self, start_type):
      """
      changes service start type

      start_type must be one of:
         win32service.SERVICE_DISABLED
         win32service.SERVICE_AUTO_START
         win32service.SERVICE_DEMAND_START
      """

      assert start_type in (win32service.SERVICE_DISABLED,
                            win32service.SERVICE_AUTO_START,
                            win32service.SERVICE_DEMAND_START)

      win32service.ChangeServiceConfig(
         self._svc_handle, # handle of service
         win32service.SERVICE_NO_CHANGE,  # svc type
         start_type,  # svc start type
         win32service.SERVICE_NO_CHANGE,  # error control
         None,  # binary path
         None,  # load order group
         0,     # tag ID
         None,  # dependencies
         None,  # account name
         None,  # account password
         None)  # display name

   def __exit__(self, *exc):
      self.close()

   def close(self):
      '''
      Close service handles.
      '''
      if self._svc_handle is not None:
         win32service.CloseServiceHandle(self._svc_handle)
      if self._scm is not None:
         win32service.CloseServiceHandle(self._scm)

      self.__reset_svchandles()


class FileBuffer(object):
   """
   Implements a class which provides interfaces for reading the file,
   updating the file and writing a file
   """
   def __init__(self, file_buffer=None):
      self.file_buffer = None

   def readFile(self, file_name):
      """
      read filecontents into file_buffer
      """
      try:
         with codecs.open(file_name, encoding='utf-8', mode='r') as f:
            self.file_buffer = f.readlines()
      except Exception as e:
         errMsg = _T('install.ciscommon.filebuffer.read',
                     "Failed to read file %s. Exception: %s")
         loErrMsg = localizedString(errMsg, [file_name, str(e)])
         raise BaseInstallException(ErrorInfo([loErrMsg]))

   def writeFile(self, file_name):
      """
      write filecontents into file_buffer
      """
      if not self.file_buffer:
         self.file_buffer = []
      try:
         with codecs.open(file_name, encoding='utf-8', mode='w') as f:
            for line in self.file_buffer:
                if line.isspace():
                   continue
                if not line.endswith('\n'):
                   line = line + '\n'
                # Python 3 hack, string has no decode() function.
                if sys.version_info < (3,0,0) and isinstance(line, str):
                   line = line.decode('utf-8')
                f.write(line)
            f.flush()
            os.fsync(f.fileno())
      except Exception as e:
         errMsg = _T('install.ciscommon.filebuffer.write',
                     "Failed to write to file %s. Exception: %s")
         loErrMsg = localizedString(errMsg, [file_name, str(e)])
         raise BaseInstallException(ErrorInfo([loErrMsg]))


   def replaceBuffer(self, file_buffer):
      """
      replaces the file_buffer
      """
      self.file_buffer = file_buffer

   def appendToBuffer(self, file_buffer):
      """
      appends contents to file_buffer
      """
      if not self.file_buffer:
         self.file_buffer = []
      self.file_buffer.extend(file_buffer)

   def updateBuffer(self, file_buffer, start=None, end=None):
      """
      update file_buffer contents between start and end
      """

      if self.file_buffer is None:
         self.file_buffer = []

      if start is None and end is None:
         self.replaceBuffer(file_buffer)
         return

      if start is None and end is not None:
         self.file_buffer[end] = file_buffer
         return

      if start is not None and end is None:
         self.file_buffer[start] = file_buffer
         return

      if start > len(self.file_buffer) or end > len(self.file_buffer):
         self.file_buffer = file_buffer
      else:
         self.file_buffer[start:end] = file_buffer

   def getBufferContents(self, start=None, end=None):
      """
      returns file_buffer contents between start and end
      """
      if self.file_buffer is None:
         self.file_buffer = []

      if start is None and end is None:
         return self.file_buffer

      if start is None and end is not None:
         if end > len(self.file_buffer):
            return []
         return self.file_buffer[end]

      if start is not None and end is None:
         if start > len(self.file_buffer):
            return []
         return self.file_buffer[start]

      if start > len(self.file_buffer) or end > len(self.file_buffer):
         return []
      else:
         return self.file_buffer[start:end]

   def getBufferContentsByPattern(self, pat):
      """
      returns the list of matches based on the pattern
      """
      ret_buf = []
      if not self.file_buffer:
         self.file_buffer = []
      for line in self.file_buffer:
         if re.search(pat, line):
            ret_buf.append(line)
      return ret_buf

   def getFirstMatch(self, pat):
      """
      returns the index of first match
      """
      ret_idx = None
      if not self.file_buffer:
         self.file_buffer = []
      idx = 0
      for line in self.file_buffer:
         if re.search(pat, line):
            ret_idx = idx
            break
         idx = idx + 1

      return ret_idx

   def getFirstMatchObject(self, pat):
      """
      returns the MatchObject of the first match
      """
      if not self.file_buffer:
         self.file_buffer = []
      for line in self.file_buffer:
         match = re.search(pat, line)
         if match:
            return match
      return None

   def findAndReplaceOne(self, pat, update):
      """
      finds the first match for pat and replaces it with update
      """
      # Python 3 hack, string has no decode() function.
      if sys.version_info < (3,0,0) and isinstance(update, str):
         update = update.decode('utf-8')
      buf_idx = self.getFirstMatch(pat)
      if buf_idx == None:
         log_error("Warning: %s placeholder not found" % pat)
         return False

      contents = self.getBufferContents(buf_idx)
      self.updateBuffer(contents.replace(pat, update), buf_idx)
      return True

   def findAndReplaceOneByRegEx(self, pat, update):
      """
      finds the first match for pat and replaces it with update
      """
      # Python 3 hack, string has no decode() function.
      if sys.version_info < (3,0,0) and isinstance(update, str):
         update = update.decode('utf-8')
      buf_idx = self.getFirstMatch(pat)
      if buf_idx == None:
         log_error("Warning: %s placeholder not found" % pat)
         return False

      contents = self.getBufferContents(buf_idx)
      self.updateBuffer(re.sub(pat, update, contents), buf_idx)
      return True

   def findAndReplace(self, pat, update):
      """
      Find and replaces all instances of the specified pattern with update
      """
      # Python 3 hack, string has no decode() function.
      if sys.version_info < (3,0,0) and isinstance(update, str):
         update = update.decode('utf-8')
      self.updateBuffer([line.replace(pat, update) for line in self.file_buffer])

   def findAndReplaceAllByRegEx(self, pat, update):
      """
      Find and replaces all instances of the specified regex pattern with update
      """
      # Python 3 hack, string has no decode() function.
      if sys.version_info < (3,0,0) and isinstance(update, str):
         update = update.decode('utf-8')
      self.updateBuffer([re.sub(pat, update, line) for line in self.file_buffer])

   def updateKeyValue(self, key, value):
      """
      finds the first match for the key\s=* and replaces it with key=value
      """
      # Python 3 hack, string has no decode() function.
      if sys.version_info < (3,0,0) and isinstance(value, str):
         value = value.decode('utf-8')
      pat = "(\s*" + re.escape(key) + "\s*=\s*)(.*)"
      buf_idx = self.getFirstMatch(pat)
      if buf_idx == None:
         log_error("Warning: Key - %s not found" % key)
         return False
      self.updateBuffer('%s=%s' % (key, value), buf_idx)
      return True

   def addOrUpdateProps(self, props):
      """
      adds or updates the properties in props
      """
      file_buffer = self.getBufferContents()
      new_buffer = []
      for line in file_buffer:
         found = False
         for k in props:
            pat = "^(\s*" + re.escape(k) + "\s*=\s*)(.*)"
            if re.search(pat, line):
               found = True
               break
         if not found:
            new_buffer.append(line)

      for k, v in props.items():
          # Python 3 hack, string has no decode() function.
         if sys.version_info < (3,0,0) and isinstance(v, str):
            v = v.decode('utf-8')
         new_buffer.append('%s=%s' % (k, v))
      self.replaceBuffer(new_buffer)

   def clearBuffer(self):
      self.file_buffer = None

def isFirewallSvcRunning():
   try:
      fwSvcControl = CISWinServiceControl('MpsSvc')
      fwSvcControl.open()
      return fwSvcControl.get_service_state() == win32service.SERVICE_RUNNING
   except pywintypes.error as e:
      log_error("Failed to determine if firewall service is running. Details: %s" % e)
      raise
   finally:
      fwSvcControl.close()

def _winOpenPort(port, protocol, name):
   if(sys.getwindowsversion()[0:2] >= (6,0)):
      command = ["netsh",
                 "advfirewall",
                 "firewall",
                 "add",
                 "rule",
                 "protocol=%s" % protocol,
                 "localport=%s" % port,
                 "name=%s" % name,
                 "dir=in",
                 "action=allow",
                 "profile=any"]
   else:
      command = ["netsh",
                 "firewall",
                 "add",
                 "portopening",
                 "protocol=%s" % protocol,
                 "port=%s" % port,
                 "name=%s" % name,
                 "mode=enable",
                 "profile=ALL"]
   log("Opening port : %s" % port)
   rc, output, error = run_command(command)
   if rc:
      # Python 3 hack, string has no decode() function.
      if sys.version_info < (3, 0, 0) and isinstance(error, str):
         error = error.decode(sys.getfilesystemencoding())
      error_str = "%s, %s" % (output, error)
      raise WindowsPortException(error_str, port)

def _winClosePort(port, protocol, name=""):
   if(sys.getwindowsversion()[0:2] >= (6,0)):
      log("Closing port : %s" % port)
      # include name in delete call if it is specified
      if(name != ""):
         command = ["netsh",
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    "protocol=%s" % protocol,
                    "localport=%s" % port,
                    "name=%s" % name]
      else:
         command = ["netsh",
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    "protocol=%s" % protocol,
                    "localport=%s" % port]
      rc, output, error = run_command(command)
      #We don't really care if the port actually closed or not.
      #Deal with it when time comes. check rc status
      if rc:
         #just log and return, don't raise exception here.
         log("Could not close ports for port with port number: " + str(port)
             + " and name: " + name)
   else:
      log("Not closing ports on Windows Server 2008 or earlier version")

def open_port(port, protocol, name, fwcheck=True):
   if os.name == 'posix':
      raise NotImplementedException("open_port not implemented for posix")
   else:
      if fwcheck and not isFirewallSvcRunning():
         log("Windows Firewall service is not running. Won't attempt to open port %d" % port)
         return
      _winOpenPort(port, protocol, name)

def close_port(port, protocol, name=""):
   if os.name == 'posix':
      raise NotImplementedException("close_port not implemented for posix")
   else:
      _winClosePort(port, protocol, name)

#
# Networking functions
#

def isIPAddress(addr):
   """
   Returns True iff addr is an IPv4 or IPv6 address.
   """
   try:
      ip = ipaddr.IPAddress(addr)
      return True
   except:
      pass
   return False

def getSrvStartType(service, quiet=False):
   """
   On cloudvm: service start mode is determined using 'chkconfig srv_name' on
   SLES11 and via 'systemctl is-enabled srv_name' on systemd services.
   On ciswin: service configuration is checked from SCM. The call QuerySeriveConfig
   return a tuple. The second element of that tuple contains the startMode type.
   """
   startType = 'UNKNOWN'

   # if vmon is enabled the start type from vmon manager
   if is_svc_vmon_integrated(service):
      cis_vmon =  CISVmonServiceControl(service)
      rc, startType, stdout, stderr = cis_vmon.get_service_start_type()
      # if rc == vMonError.VMON_ERRNO_SUCCESS:
         # format AUTOMATIC ---> Automatic
      return startType.capitalize()
      # else:
      #    log_error('Error: Invalid input provided to get startType of'
      #              'service %s.' % service)
      # raise Exception('Error: startType of svc: %s rc : %s stdout: %s '
      #                 'stderr: %s' % (service, rc, stdout, stderr))

   if os.name == 'posix':
      # On systemd systems following us the start type contract
      # AUTOMATIC = enabled
      # MANUAL = disabled
      # DISABLED = masked
      cmd = [_systemctl_path, 'is-enabled', service]
      rc, stdout, stderr = run_command(cmd, quiet=quiet)
      if rc == 0:
         startType = 'Automatic'
      else:
         # rc is 1 for non enabled services.
         stdout = stdout.strip()
         if stdout == 'masked':
            startType = 'Disabled'
         elif stdout == 'disabled':
            startType = 'Manual'

      if startType == 'UNKNOWN':
         if rc != 0:
            log_error("ERROR executing %s, %s, %s" % (cmd, stdout, stderr),
                      quiet)
            raise  Exception("Unable to get %s startType. Error %s" %
                             (service, stderr))
         raise Exception("Unknown start type %s for service %s" %
                         stdout, service)
   else:
      hscm = None
      hservice = None
      try:
         hscm = win32service.OpenSCManager(None, None, win32con.GENERIC_READ)
         hservice =  win32service.OpenService(hscm, service,
                        win32service.SERVICE_QUERY_CONFIG)
         config = win32service.QueryServiceConfig(hservice)
         startType = config[1]
      except pywintypes.error as e:
         log_error(e)
      finally:
         if hscm != None:
            win32service.CloseServiceHandle(hscm)
         if  hservice != None:
            win32service.CloseServiceHandle(hservice)

      if  startType == "UNKNOWN":
         raise  Exception("Unable to get %s startType:%s" %
                          (service, startType))
      if startType == win32service.SERVICE_DISABLED:
         startType = "Disabled"
      elif startType == win32service.SERVICE_DEMAND_START:
         startType = "Manual"
      elif startType ==  win32service.SERVICE_AUTO_START:
         startType = "Automatic"

   return startType

def getUrlAddr(addr):
   """
   Given an network addr returns a corresponding string which can be used in
   URLs.
   """
   urlAddr = ''
   try:
      ip = ipaddr.IPAddress(addr)
      urlAddr = "[" + addr + "]" if ip.version == 6 else addr
   except:
      urlAddr = addr
   return urlAddr

class StartType:

   DISABLED = 'Disabled'
   MANUAL = 'Manual'
   AUTO = 'Automatic'

   if os.name != 'posix':
      WIN32 = {
         DISABLED: win32service.SERVICE_DISABLED,
         MANUAL: win32service.SERVICE_DEMAND_START,
         AUTO: win32service.SERVICE_AUTO_START
      }


def get_winregistry(keyRoot, variable):
   """
   Return window registry variable value.
   """
   reg_val = None
   try:
       regRoot = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
       with _winreg.OpenKey(regRoot, keyRoot) as regKey:
          value, type  = _winreg.QueryValueEx(regKey, variable)
          reg_val =  value
   except  Exception as e:
       msg = "Unable to read registry entry. Error: %s" % e
       log_error(msg)
   finally:
       if regRoot:
           _winreg.CloseKey(regRoot)
   return reg_val


def set_winregistry(keyRoot, sub_key, value, reg_type=None):
   """
   Set window registry subkey value.
   """
   status = False
   if reg_type is None:
       reg_type = _winreg.REG_SZ
   try:
      regRoot = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
      with _winreg.OpenKey(regRoot, keyRoot, 0, _winreg.KEY_SET_VALUE) as regKey:
         _winreg.SetValueEx(regKey, sub_key, 0, reg_type, value)
         status = True
   except  Exception as e:
      msg = "Unable to set registry entry. Error: %s" % e
      log_error(msg)
      status = False
   finally:
      if regRoot:
          _winreg.CloseKey(regRoot)
   return status
