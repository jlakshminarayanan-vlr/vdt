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
__version__ = "1.1.4"
testkb = "https://kb.vmware.com/s/article/80469"
import io
import sys
import argparse
import atexit
import textwrap as _textwrap
import logging.config
from importlib import import_module
import socket
from lib.utils import *
from lib.pformatting import *
import datetime
import time
try:
    import configparser
except:
    import ConfigParser as configparser

sys.path.append(os.environ['VMWARE_PYTHON_PATH'])
from cis.defaults import get_cis_log_dir

workingdir = os.path.dirname(os.path.abspath(__file__))
logconfig = os.path.join(workingdir,'cfg','config_log.ini')

scripts_dir = os.path.join(workingdir, 'scripts')
sys.path.append(os.path.abspath(scripts_dir))
logdir = os.path.join(get_cis_log_dir(), 'vdt')
logname = 'vdt-report'
params = {}



def _setFilename(name):
    """
    Sets filename in a helpful format
    
    Args:
        name (str): file name
        file_type (str): file extension
    
    Returns:
        str: string containing full file path.  compatible with windows and appliance
    """
    file_name = str(time.strftime(logname + "-%Y-%m-%d-%H%M%S"))
    path = logdir + '/' + file_name
    path = path.replace('\\','/')
    return path

def getLogLevel():
    config = configparser.ConfigParser()
    try:
        config.read_file(open(logconfig))
    except:
        config.readfp(open(logconfig))
    return config.get('handler_FileHandler', 'level')

def setDebug(value=False):
    config = configparser.ConfigParser()
    try:
        config.read_file(open(logconfig))
    except:
        config.readfp(open(logconfig))
    if value:
        config.set('handler_FileHandler', 'level', 'DEBUG')
    else:
        config.set('handler_FileHandler', 'level', 'INFO')
    with open(logconfig,'w') as configfile:
        config.write(configfile)

def setloggingparams():
    logfile = _setFilename(logname)
    mylogfile = os.path.abspath(os.path.join(logdir,logfile))
    config = configparser.ConfigParser()
    try:
        config.read_file(open(logconfig))
    except:
        config.readfp(open(logconfig))
    config.set('PARAMS', 'LOGFILE', mylogfile)
    with open(logconfig,'w') as configfile:
        config.write(configfile)

def getloggingparams():
    config = configparser.ConfigParser()
    try:
        config.read_file(open(logconfig))
    except:
        config.readfp(open(logconfig))
    result = config.get('PARAMS','LOGFILE')
    if result == "None":
        setloggingparams()
        getloggingparams()
    return config.get('PARAMS','LOGFILE')

logfile = _setFilename(logname)
def _update_vm_support():
    """
    Utility function to include vdt log directory in support bundles.
    """
    mfx = """
% Manifest name: vdt
% Manifest group: VirtualAppliance
% Manifest default: Enabled
# action Options file/command
copy IGNORE_MISSING {logdir}/*
    """.format(logdir=logdir)
    vmsupportpath = os.path.join(os.environ['VMWARE_CFG_DIR'], 'vm-support','vdt.mfx')
    if not os.path.exists(vmsupportpath):
        try:
            with open(vmsupportpath,"w+") as f:
                f.writelines(mfx)
            logger.debug("vdt logs will be included in support bundles.")
        except:
            error_msg = "Couldn't add support bundle config file: %s" % vmsupportpath
            logger.error("You will have to collect vdt logs manually!  Error was: %s" % error_msg)
    else:
        logger.debug("%s already exists." % vmsupportpath)

def _createDirs(dir_name):
    """
    Utility function to create a directory.

    Args:
        dir_name (str): directory name
    
    """
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

def loadJson(file):
    """
    Utility function to load a json file.
    
    Args:
        file (str): Path to json file
    
    Returns:
        dict: Returns the json as a dictionary
    """
    file = os.path.abspath(file)
    with open(file) as f:
        jsondata = json.load(f)
    return jsondata

def setupLogging():
    """
    Utility function to set up the logging (creates directories, sets the filename, loads log config)
    """
    _createDirs(logdir)
    logfilename = getloggingparams()
    
    logging.config.fileConfig(logconfig, defaults={'filename': logfilename}, disable_existing_loggers=False)

def parameters():
    """
    Utility function to load parameters from lib.utils.get_params()
    
    Returns:
        dict: local node parameters as a dictionary
    """
    params = get_params()
    return params.get()

class LineWrapRawTextHelpFormatter(argparse.RawDescriptionHelpFormatter):

    """
    Utility to properly display help text with proper line wrapping.
    """
    
    def _split_lines(self, text, width):
        """
        Args:
            text (str): Text to wrap properly
            width (str): Width of the text
        
        Returns:
            str: wrapped help text
        """
        text = self._whitespace_matcher.sub(' ', text).strip()
        return _textwrap.wrap(text, width)

# def prompt():

#     username = "administrator@" + parameters()['domain_name']
#     # Get password with no echo
#     print("")
#     passwd = getpass.getpass("\nProvide password for %s: " % username)
#     return username, passwd

def escape_ansi(line):
    ansi_escape =re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
    return ansi_escape.sub('', line)

_DefaultCommmandEncoding = sys.getfilesystemencoding()
def run_command(cmd, stdin=None, quiet=False, close_fds=False,
                encoding=_DefaultCommmandEncoding, log_command=True):

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    if sys.version_info[0] >= 3 and isinstance(stdin, str):
        stdin = stdin.encode(encoding)
    stdout, stderr = process.communicate(stdin)
    return stdout.decode('utf-8'),stderr.decode('utf-8')
class LineWrapRawTextHelpFormatter(argparse.RawDescriptionHelpFormatter):
    
    def _split_lines(self, text, width):

        text = self._whitespace_matcher.sub(' ', text).strip()
        return _textwrap.wrap(text, width)

def parse_argument():
    parser = argparse.ArgumentParser(description='vSphere Diagnostic Tool',
                                 formatter_class=
                                 LineWrapRawTextHelpFormatter)

    parser.add_argument("-d", "--debug",
                            action='store_true',
                            help="Include debug logging")
    
    parser.add_argument("-i", "--interactive",
                            action='store_true',
                            help="Pause after each check")

    parser.add_argument("-f", "--force",
                            action='store_true',
                            help="Override cautions")
    return parser

def set_force_flag(enabled=False):
    if enabled:
        os.environ['VDT_FORCE'] = "TRUE"
    else:
        if 'VDT_FORCE' in os.environ:
            del os.environ['VDT_FORCE']


class CompatStringIO(io.StringIO):
    # see https://labs.windriver.com/downloads/toolkit/wrdbg_tools/lib/python/doc/html/wrdbg/porting.html
    def write(self, s):
        if hasattr(s, 'decode'):
            # Should be python 2
            return int(super(CompatStringIO, self).write(s.decode('utf-8')))
        else:
            return super(CompatStringIO, self).write(s)
    def getvalue(self):
        return str(super(CompatStringIO, self).getvalue())


def Vdt(debug=False, interactive=False, force=False):
    """
    Main entry function.  Parses arguments and calls the appropriate wrapper.  Also displays the warning messages.
    """
    if debug:
        setDebug(True)
        atexit.register(setDebug)
    if force:
        set_force_flag(force)
        atexit.register(set_force_flag)
    print(color_wrap("RUNNING PULSE CHECK",'title'))
    username = ""
    password = ""
    _date = datetime.date.today().strftime("%A, %B %d")
    t = time.localtime()
    _time = time.strftime("%H:%M:%S",t)
    


    setloggingparams()
    setupLogging()
    logger = logging.getLogger(__name__)

    _update_vm_support()
    
    runtime_today = "Today: %s %s" % (_date,_time)
    myversion = "Version: %s" % __version__
    myloglevel = "Log Level: %s" % getLogLevel()
    print(runtime_today)
    print(myversion)
    print(myloglevel)
    logger.info(' '.join([runtime_today, myversion, myloglevel]))

    global params

    try:
        params = parameters()
    except:
        print("Couldn't get parameters.  Is vmdir running?")
        pass

    ssocheck = ['embedded','infrastructure']
    if 'deploytype' in params:

        try:
            username,password = prompt()
        except:
            username = ""
            password = ""

    for script in sorted(os.listdir(scripts_dir)):
        
        if '__init__' not in script:

            interpreter = ""

            if script.endswith('.sh'):
                interpreter = "/bin/bash"
            elif script.endswith('.py'):
                interpreter = "/usr/bin/python"
            else:
                continue
            command_file = os.path.join(scripts_dir, script)
            logger.info("Running %s" % script)
            if '.py' in script:
                imp = import_module(script.rsplit(".",1)[0])
                print(color_wrap(imp.__title__, 'title'))
                logger.info("\n" + escape_ansi(color_wrap(imp.__title__, 'title')))
                if 'auth' in script:
                    runnable = getattr(imp,'main_wrap')
                    old_stdout = sys.stdout
                    # new_stdout = io.StringIO()
                    new_stdout = CompatStringIO()
                    sys.stdout = new_stdout 
                    runnable(username,password)
                    output = new_stdout.getvalue()
                    errors = ""
                    sys.stdout = old_stdout
                else:
                    mycommand = [interpreter, command_file]
                    try:
                        # logger.info("Running %s" % script)
                        if force:
                            output, errors = run_command(mycommand)
                        else:
                            output, errors, timedout = Command(mycommand).run()
                            if timedout:
                                msg = "Running script: %s timed out.  Please re-run with --force." % command_file
                                formResult(color_wrap('[FAIL]', 'fail'), msg)
                                logger.error(msg)
                                continue
                    except:
                        print("Failed to run command %s" % command_file)
                        raise

            else:
                with open(command_file) as f:
                    lines = f.readlines()
                for line in lines:
                    if '__title__' in line:
                        title = line.split('=', 1)[1].replace('\"','')
                        title = title.replace("\n","")
                print(color_wrap(title, 'title'))
                logger.info("\n" + escape_ansi(color_wrap(title, 'title')))
                mycommand = [interpreter, command_file]
                try:
                    
                    if force:
                        output, errors = run_command(mycommand)
                    else:
                        output, errors, timedout = Command(mycommand).run()
                        if timedout:
                            msg = "Running script: %s timed out.  Please re-run with --force." % command_file
                            formResult(color_wrap('[FAIL]', 'fail'), msg)
                            logger.error(msg)
                            continue
                except:
                    print("Failed to run command %s" % command_file)
                    raise
            
            if output != 'None':
                print(output)
                logger.info("\n" + escape_ansi(output))
                if errors:
                    logger.debug("%s threw errors!:\n%s" % (script, escape_ansi(errors)))
            else:
                print(errors)
                logger.error("\n" + escape_ansi(errors))
            if interactive:
                try:
                    raw_input("Press Enter to continue...")
                except:
                    input("Press Enter to continue...")

    print("Report written to %s" % os.path.abspath(os.path.join(logdir,logfile)))
    print("Please send feedback / feature requests to project_pulse@vmware.com")

if __name__ == '__main__':
    args = parse_argument().parse_args()

    Vdt(args.debug, args.interactive, args.force)
    
