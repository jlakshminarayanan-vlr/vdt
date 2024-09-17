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

import sys
import glob
import os, errno
import tempfile
import argparse
import logging
import time
import warnings
import traceback
import json
from contextlib import contextmanager
import xml.etree.ElementTree as ElementTree
import socket
import datetime
import time
import traceback
import ssl
import copy
import getpass
import threading
import shlex
from subprocess import Popen, PIPE
try:
    import httplib
except ImportError:
    import http.client as httplib
try:
    import urllib.parse as urlparse
    from urllib.request import Request, urlopen
    from urllib.error import URLError, HTTPError
except ImportError:
    import urlparse
    from urllib2 import Request, urlopen
    from urllib2 import URLError, HTTPError
if os.name == 'posix':
    sys.path.append('/usr/lib/vmware-vmafd/lib64')
else:
    sys.path.append(os.path.join(os.environ['VMWARE_CIS_HOME'], 'vmafdd'))
sys.path.append(os.environ['VMWARE_PYTHON_PATH'])
from OpenSSL.crypto import (load_certificate, dump_privatekey, dump_certificate, X509, X509Name, PKey)
from OpenSSL.crypto import (TYPE_DSA, TYPE_RSA, FILETYPE_PEM, FILETYPE_ASN1 )
from cis.svcsController import get_services_status
from cis.tools import *
from cis.utils import *
from cis.exceptions import (InvokeCommandException, ServiceNotFoundException,
                            SetServiceStartTypeException)
from cis.defaults import *
from cis.vecs import Service
from pyVmomi import (lookup, SoapStubAdapter, vmodl, dataservice,
                     SessionOrientedStub)
from pyVim import sso
try:
    from cisutils import getSrvStartType
    from pformatting import *
except:
    from .cisutils import getSrvStartType
    from .pformatting import *
import vmafd
if os.name != 'posix':
    if sys.version_info[0] >= 3:
        from six.moves import winreg
    else:
        import _winreg as winreg
    import win32api
    import win32con
    import win32service
    import win32security
    import win32net
    import ntsecuritycon as con

logger = logging.getLogger(__name__)
command_timeout = 10
usage = ''
VMWARE_PRODUCT_ID = 'com.vmware.cis'
SSO_TYPE_ID = 'cs.identity'
EP_SSO_PROTOCOL = 'wsTrust'
EP_SSO_TYPE_ID = 'com.vmware.cis.cs.identity.sso'
AUTHZ_TYPE_ID = 'cs.authorization'
EP_AUTHZ_PROTOCOL = 'vmomi'
EP_AUTHZ_TYPE_ID = 'com.vmware.cis.authorization.server'
SYSTEM_HOSTNAME = socket.getfqdn()

comp_path = get_component_home_dir(def_by_os('vmafd', 'vmafdd'))
vmafd_cli_path = def_by_os(os.path.join(comp_path, 'bin/vmafd-cli'),
            os.path.join(comp_path, 'vmafd-cli.exe'))
QUIET = True
SERVICE_INFO_PROPERTIES = ["serviceVersion", "serviceId", "siteId",
                           "serviceNameResourceKey", "serviceNameDefault",
                           "serviceDescriptionResourceKey", "serviceDescriptionDefault",
                           "vendorNameResourceKey", "vendorNameDefault",
                           "vendorProductInfoResourceKey", "vendorProductInfoDefault",
                           "ownerId", "nodeId", ]
if is_linux():
        idm_lib_dir = os.path.normpath('/opt/vmware/lib64/')
        SSO_HOSTNAME_FILE = "/etc/vmware-sso/hostname.txt"
        OS_TYPE = "vcsa"
else:
        idm_lib_dir = os.path.normpath(get_cis_install_dir() + '/VMware Identity Services/')
        SSO_HOSTNAME_FILE = os.environ['VMWARE_CFG_DIR'] + "\\sso\\hostname.txt"
        OS_TYPE = "windows"

java_home = get_java_home()
javaBin = os.path.join(java_home, "bin", def_by_os("java", "java.exe"))
cis_home = get_cis_install_dir()
sso_home = os.path.join(cis_home, "vmware-sso")
common_lib_dir = os.path.join(sso_home, "commonlib")
common_lib = os.path.join(common_lib_dir, "*")
idm_lib = os.path.join(idm_lib_dir, "*")
curpath = os.getcwd()


if is_windows():
    class_path = '"%s;%s:.;*"' % (idm_lib, common_lib)
else:
    class_path = '%s:%s:.:*' % (idm_lib, common_lib)
_DefaultCommmandEncoding = sys.getfilesystemencoding()

class Command(object):
    # Based on jcollado's solution:
    # http://stackoverflow.com/questions/1191374/subprocess-with-timeout/4825933#4825933
    def __init__(self, cmd, stdin=None, quiet=False, close_fds=False, encoding=_DefaultCommmandEncoding, shell=False, response=None):
        self.shell = shell
        self.stdin = stdin
        self.encoding = encoding
        try:
            if isinstance(cmd, basestring):
                cmd = shlex.split(cmd)
        except:
            if isinstance(cmd,str):
                cmd = shlex.split(cmd)
        self.cmd = cmd
        self.process = None
        self.error = None
        self.response = response

    def run(self):
        timedout = False
        def target():
            if sys.version_info[0] >= 3 and isinstance(self.stdin, str):
                self.stdin = self.stdin.encode(self.encoding)
            if self.response:
                self.process = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=self.shell)
                self.process.stdin.write(self.response.encode(self.encoding))
            else:
                self.process = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=self.stdin, shell=self.shell)
            self.output, self.error = self.process.communicate(self.stdin)

        thread = threading.Thread(target=target)
        thread.start()
        thread.join(command_timeout)
        if thread.is_alive():
            self.process.terminate()
            thread.join()
        if self.process.returncode != 0:
            if len(self.error.decode()) <= 0:
                timedout = True
                # formResult(color_wrap("[FAIL]","fail"), "CMD %s timed out because it took too long." % self.cmd[0])
        return self.output.decode('utf-8'), self.error.decode('utf-8'), timedout

def getStartup(service):
    result = ""
    logger.debug("Getting startup type of service %s" % service)
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
    logger.debug(result)
    return result

def getMultiServiceStatus(svcs=None):
    svcslist = ' '.join(svcs)
    logger.debug("Getting startup type of service %s" % svcslist)
    result = get_services_status(svcs)
    logger.debug(result)
    return result

def getSingleServiceStatus(service):
    logger.debug("Getting status of service %s" % service)
    for x,y in get_services_status([service]).items():
        if len(y) == 2:
            status = y[0]
        else:
            status = y
    logger.debug(status)
    if status == 'RUNNING':
        return True
    else:
        return False

class FailedCommand(Exception):
    """
    Helps when handling command failures.
    """
    def __init__(self, cmd, error, msg="Command failed!"):
        self.cmd = cmd
        self.error = error
        self.msg = msg
        super().__init__(self.msg)

def _getVersion():
    logger.debug("getting version")
    if is_windows():
        aReg = winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE)
        key = winreg.OpenKey(aReg, r"SOFTWARE\VMware, Inc.\vCenter Server")
        build = winreg.QueryValueEx(key,'BuildNumber')[0]
        version = winreg.QueryValueEx(key,'ProductVersion')[0]
        
    else:
        with open("/etc/applmgmt/appliance/update.conf") as f:
            data = json.load(f)
        build = data['build']
        f = open("/etc/issue")
        for line in f:
            if not line.strip():
                continue
            else:
                version = line
                break
        version = version.rsplit(' ',1)[1]
        version = version.strip()
    logger.debug(version + build)
        
    return version, build

logdir = os.path.join(get_cis_log_dir(), 'vdt')

###############################################################
#    Beginning utility functions provided by cisreglib.py     #
###############################################################

def prompt():
    parameters = get_params().get()
    if 'ERROR' in parameters['domain_name']:
        raise Exception("Failed to get domain name.  Is vmdir/vmafdd running?")
    username = "administrator@" + parameters['domain_name']
    # Get password with no echo
    passwd = getpass.getpass("\nProvide password for %s: " % username)
    return username, passwd

class VmafdClient(object):
    """
    A helper class to get information from vmafd
    
    Attributes:
        client (vmafd client object, optional): Client connection made to VMAFD api.
    """
    def __init__(self):

        try:
            self.client = vmafd.client('localhost',quiet=True)
            try:
                self.client.GetStatus()
                # print(dir(self.client.GetStatus()))
            except RuntimeError as e:
                logging.debug('Failed to create vmafd client!  Is vmafdd running?')
                print(color_wrap("Failed to create vmafd client!  Is vmafdd running?",'fail'))
                sys.exit()
                # raise


        except Exception as e:
            # The API seems to not work in case of 60 to 65 windows upgrade.
            # As a backup till we figure out why, use CLIs which do work
            # correctly
            pass
        self.client = None
    
    def run_commands(self, cmd, quiet=False, failuremsg=""):
        """
        Makes the error handling a bit better...
        """
        ret, stdout, stderr = run_command(cmd, quiet=quiet)
        if ret != 0:
            raise FailedCommand(str(cmd), stderr)
        else:
            return stdout


    def get_ls_location(self):
        """
        Returns LookupService URL
        """
        logger.debug("Getting ls location")
        if self.client:
            return self.client.GetLSLocation()
        else:
            vmafd_cli_path = self._get_vmafd_cli_path()
            try:
                return self.run_commands([vmafd_cli_path, 'get-ls-location',
                                   '--server-name', 'localhost'],quiet=True).strip()
                logger.debug("Success")
            except FailedCommand as e:
                logger.debug(e.error)
                sys.exit(1)

    def get_domain_name(self):
        """
        Returns SSO domain name (i.e. vsphere.local)
        """
        logger.debug("Getting SSO domain name")
        if self.client:
            return self.client.GetDomainName()
        else:
            vmafd_cli_path = self._get_vmafd_cli_path()
            try:
                return self.run_commands([vmafd_cli_path, 'get-domain-name',
                                   '--server-name', 'localhost'],quiet=True).strip()
                logger.debug("Success")
            except FailedCommand as e:
                logger.debug(e.error)
                sys.exit(1)
    def get_pnid(self):
        """
        Returns PNID (primary network ID) of node
        """
        logger.debug("Getting pnid")
        vmafd_cli_path = self._get_vmafd_cli_path()
        try:
            return self.run_commands([vmafd_cli_path, 'get-pnid',
                                   '--server-name', 'localhost'],quiet=True).strip()
            logger.debug("Success")
        except FailedCommand as e:
            logger.debug(e.error)
            sys.exit(1)
    def get_machine_id(self):
        """
        Returns machine ID of node
        """
        logger.debug("Getting machine ID")
        vmafd_cli_path = self._get_vmafd_cli_path()
        try:
            return self.run_commands([vmafd_cli_path, 'get-machine-id',
                                   '--server-name', 'localhost'], quiet=True).strip()
            logger.debug("Success")
        except FailedCommand as e:
            logger.debug(e.error)
            # print("Failed to get machine ID!  Is vmdird running?")
            sys.exit(1)

    def get_site_name(self):
        """
        Returns the SSO site to which this node belongs.
        """
        logger.debug("Getting site name")
        vmafd_cli_path = self._get_vmafd_cli_path()
        try:
            return self.run_commands([vmafd_cli_path, 'get-site-name',
                                   '--server-name', 'localhost'],quiet=True).strip()
            logger.debug("Success")
        except FailedCommand as e:
            logger.debug(e.error)
            sys.exit(1)
    def _get_vmafd_cli_path(self):
        """
        Returns vmafd cli path appropriate for the current OS.
        """
        comp_path = get_component_home_dir(def_by_os('vmafd', 'vmafdd'))
        return def_by_os(os.path.join(comp_path, 'bin/vmafd-cli'),
                         os.path.join(comp_path, 'vmafd-cli.exe'))


    def get_node_id(self):
        """
        Returns the LDU GUID AKA node ID.
        """
        logger.debug("Getting node ID")
        nodeid = get_install_parameter('vmdir.ldu-guid', '', quiet=True)
        logger.debug("Success")
        return nodeid

class SsoClient(object):
    """
    Simple class with methods to create security context for privileged
    requests.
    """
    def __init__(self, sts_url, sts_cert_data, uname, passwd, cert=None,
                 key=None):
        """
        Args:
            sts_url (TYPE): Description
            sts_cert_data (TYPE): Description
            uname (TYPE): Description
            passwd (TYPE): Description
            cert (None, optional): Description
            key (None, optional): Description
        """
        logger.debug("Setting SSO client")
        self._uname = uname
        self._passwd = passwd
        self._sts_url = sts_url
        self._sts_cert_file = None
        self._key_file = None
        self._cert_file = None
        self._saml_token = None

        with tempfile.NamedTemporaryFile(delete=False) as tempfp:
            tempfp.write(sts_cert_data.encode('utf-8'))
            self._sts_cert_file = tempfp.name

        if key:
            with tempfile.NamedTemporaryFile(delete=False) as tempfp:
                tempfp.write(key.encode('utf-8'))
                self._key_file = tempfp.name

        if cert:
            with tempfile.NamedTemporaryFile(delete=False) as tempfp:
                tempfp.write(cert.encode('utf-8'))
                self._cert_file = tempfp.name

    def _update_saml_token(self):
        """
        Helper method which fetches SAML token by talking to sts service
        and updates self._saml_token
        """
        sts_auth = sso.SsoAuthenticator(
            self._sts_url)

        if self._uname and self._passwd:
            # Bearer token based on given user credentials.
            self._saml_token = sts_auth.get_bearer_saml_assertion(
                self._uname, self._passwd, token_duration=120)
        else:
            # Get HOK token based on given service user cert and key.
            self._saml_token = sts_auth.get_hok_saml_assertion(
                self._cert_file, self._key_file, delegatable=True,
                token_duration=120)

    @contextmanager
    def securityctx_modifier(self, soapStub):
        """
        Appends the security context to give soap stub adapter. It caches the
        SAML token, but refreshes it on a SecurityError exception.
        
        Args:
            soapStub (TYPE): Description
        """
        for retry in range(0, 2):
            try:
                if self._uname and self._passwd:
                    if not self._saml_token:
                        self._update_saml_token()
                    soapStub.samlToken = self._saml_token
                    yield
                else:
                    if not self._saml_token:
                        self._update_saml_token()

                    def _requestModifier(request):

                        return sso.add_saml_context(request, self._saml_token,
                                                    self._key_file)
                    # Each request must be signed with soluser's private key.
                    with soapStub.requestModifier(_requestModifier):
                        soapStub.samlToken = self._saml_token
                        yield
                break
            except vmodl.fault.SecurityError as ex:
                self._saml_token = None
                logging.error('Security error: %s' % ex)
            finally:
                soapStub.samlToken = None

    def cleanup(self):
        """
        Delete temp cert and private key files.
        """
        if self._sts_cert_file:
            os.unlink(self._sts_cert_file)
            self._sts_cert_file = None
        if self._key_file:
            os.unlink(self._key_file)
            self._key_file = None
        if self._cert_file:
            os.unlink(self._cert_file)
            self._cert_file = None

    def __del__(self):
        self.cleanup()

class LookupServiceClient(object):
    """
    Implements helper methods to talk to lookup service.
    
    Attributes:
        service_content (API): content returned by interaction with LS API
    """
    def _retry_request(req_method, *args, **kargs):

        def do_retry(self, *args, **kargs):

            for retry in range(0, self._retry_count):
                try:
                    return req_method(self, *args, **kargs)
                except socket.error as e:
                    logger.info("retrying request...")
                    if retry == self._retry_count - 1:
                        logger.error("CONNECTION TIMEOUT!  Error was: %s" % e)
                        sys.exit(1)
                    time.sleep(self._retry_delay)
        return do_retry

    @_retry_request
    def _init_service_content(self):
        """
        Initializes service content from LS API.

        """
        logger.debug("getting service instance...")
        si = lookup.ServiceInstance("ServiceInstance", self._stub)
        try:
            self.service_content = si.RetrieveServiceContent()
        except Exception as e:
            logger.error("Failed to talk to the lookup service!  STS may not be functioning properly -- Error was: %s" % e)
            sys.exit(1)
        logger.debug("Got service content.")

    def __init__(self, ls_url, retry_count=1, retry_delay=0):
        """      
        Args:
            ls_url (TYPE): Description
            retry_count (int, optional): Description
            retry_delay (int, optional): Description
        """
        logger.debug("Setting up lookup service client")
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self._retry_count = retry_count
        self._retry_delay = retry_delay
        self._sso_client = None
        logger.debug("Getting stub...")
        self._stub = SoapStubAdapter(url=ls_url, ns='lookup/2.0', sslContext=context)
        self._init_service_content()

    def set_sso_client(self, sso_client):
        """
        This needs to be called before invoking any privileged request.
        
        Args:
            sso_client (sso_client object): sso_client object
        """
        self._sso_client = sso_client

    def get_sts_endpoint_data(self):
        """
        Returns a tuple of sts url and sts node sslTrust.
        """
        logger.debug("Get STS data...")
        sts_endpoints = self.get_service_endpoints(
            SSO_TYPE_ID, ep_protocol=EP_SSO_PROTOCOL, ep_type=EP_SSO_TYPE_ID)

        if not sts_endpoints:
            raise Exception("Unable to get sts url from LS")
        return (sts_endpoints[0].url, sts_endpoints[0].sslTrust[0])

    def _privileged_request(req_method, *args, **kargs):

        def add_securityctx_to_requests(self, *args, **kargs):

            for retry in range(0, self._retry_count):
                try:
                    with self._sso_client.securityctx_modifier(self._stub):
                        return req_method(self, *args, **kargs)
                except socket.error:
                    logger.info("retrying request...")
                    if retry == self._retry_count - 1:
                        raise
                    time.sleep(self._retry_delay)
        return add_securityctx_to_requests

    @_privileged_request
    def register_service(self, svc_id, svc_create_spec):
        """
        Requires an API formatted spec and the service ID you want to register
        
        Args:
            svc_id (str): Service ID to register
            svc_create_spec (spec object): API formatted spec
        """
        logger.debug("registering service %s" % svc_id)
        self.service_content.serviceRegistration.Create(svc_id,
                                                        svc_create_spec)

    @_privileged_request
    def reregister_service(self, svc_id, svc_set_spec):
        """
        This will set the service registration (specified by service ID)
        to the newly provided API formatted spec
        
        Args:
            svc_id (str): Service ID 
            svc_set_spec (spec object): API formatted spec
        """
        logger.debug("reregistering service %s" % svc_id)
        self.service_content.serviceRegistration.Set(svc_id, svc_set_spec)

    @_privileged_request
    def unregister_service(self, svc_id):
        """
        This will delete the service registration specified by service ID
        
        Args:
            svc_id (str): Service ID 
        """
        try:
            logger.debug("unregistering service %s" % svc_id)
            self.service_content.serviceRegistration.Delete(svc_id)
        except Exception as e:
            sException = str(e);
            logging.warning('Failed to unregister_service [%s]: %s, sys.exc_info()[1]' % (svc_id,
                            sys.exc_info()[1]))
            logging.warning('Failed to unregister_service [%s]: %s, str(e)' % (svc_id, sException))
            logging.warning('Failed to unregister_service [%s]: %s, repr(e)' % (svc_id, repr(e)))
            logging.warning('Failed to unregister_service [%s]: %s, traceback.format_exc()' %
                            (svc_id, traceback.format_exc()))
            if 'not found' in sException and 'Entry with name' in sException :
                logging.warning('Failed to unregister service %s because service entry not found, '
                                'bypass the error' % svc_id)
                pass
            else:
                logging.error('Failed to unregister service %s, esclate the error' % svc_id)
                raise

    @_retry_request
    def get_service_info_list(self, svc_id=None, search_filter=None):
        """
        Returns a list of service info objects corresponding to given service
        id or search filter.
        
        Args:
            svc_id (None, optional): optionally return for specific service
            search_filter (None, optional): filter results
        
        Returns:
            ServiceInfo: API formatted list of services.
        """

        info_list = []

        if svc_id:
            logger.debug("getting service info for svc_id: %s" % svc_id)
            info_result = self.service_content.serviceRegistration.Get(svc_id)
            if info_result:
                info_list.append(info_result)
        else:
            logger.debug("getting service info with filter: %s" % search_filter)
            info_list.extend(self.service_content.serviceRegistration.List(
                search_filter))
        return info_list

    def get_local_endpointurl(self, service_endpoint):

        for ep_attr in service_endpoint.endpointAttributes:
            if ep_attr.key == 'cis.common.ep.localurl':
                return ep_attr.value
        return None

    def get_service_info_list_ex(self, pnid=None, machine_id=None):
        """
        Returns a list of service info objects corresponding given pnid
        or machine id.
        
        Args:
            pnid (str, optional): primary network identifier or FQDN of desired machine
            machine_id (str, optional): Machine ID of desired machine
        
        Returns:
            ServiceInfo list: API formatted list of services
        """
        result = []
        search_filter = lookup.ServiceRegistration.Filter()
        for svcinfo in self.get_service_info_list(search_filter=search_filter):
            if machine_id:
                for attr in svcinfo.serviceAttributes:
                    if (attr.key == 'com.vmware.cis.cm.HostId' and
                        attr.value == machine_id):
                        result.append(svcinfo)
                        break
            elif pnid and svcinfo.serviceEndpoints:
                for serviceEndpoint in svcinfo.serviceEndpoints:
                    url_comps = urlparse.urlparse(serviceEndpoint.url)
                    if url_comps.hostname == pnid.lower():
                        result.append(svcinfo)
                        break
        return result

    @_retry_request
    def get_service_endpoints(self, svc_typeid, ep_protocol=None, ep_type=None,
                              local_nodeid=None):
        """
        Retrieve service end-points according to given filter criteria
        consisting if service type id, endpoint protocol name and endpoint
        type id.
        If local_nodeid (==vmdir.ldu-guid) is specified, then local urls
        are applied to service info if present on same node and returned.
        
        Args:
            svc_typeid (str): filter by service type
            ep_protocol (None, optional): filter by endpoint protocol
            ep_type (None, optional): filter by endpoint type
            local_nodeid (None, optional): specify the node ID or ldu guid
        
        Returns:
            ServiceInfo list: API formatted list of services
        """
        filterCriteria = lookup.ServiceRegistration.Filter()
        filterCriteria.serviceType = lookup.ServiceRegistration.ServiceType()
        filterCriteria.serviceType.product = VMWARE_PRODUCT_ID
        filterCriteria.serviceType.type = svc_typeid

        if ep_protocol is not None or ep_type is not None:
            filterCriteria.endpointType =\
                lookup.ServiceRegistration.EndpointType()
            if ep_protocol is not None:
                filterCriteria.endpointType.protocol = ep_protocol
            if ep_type is not None:
                filterCriteria.endpointType.type = ep_type

        serviceRegistration = self.service_content.serviceRegistration
        result = serviceRegistration.List(filterCriteria)
        if not result:
            return None

        if not local_nodeid:
            return result[0].serviceEndpoints

        for service_info in result:
            # Apply local url to service registered with local node.
            if service_info.nodeId == local_nodeid:
                for service_ep in service_info.serviceEndpoints:
                    local_url = self.get_local_endpointurl(service_ep)
                    if local_url:
                        service_ep.url = local_url
                return service_info.serviceEndpoints
        return result[0].serviceEndpoints

    @staticmethod
    def _copy_svcspec(svcinfo, mutable_spec):
        """
        Copies svc info field values to corresponding mutable spec fields.
        
        Args:
            svcinfo (object)
            mutable_spec (object)
        """
        mutable_spec.serviceVersion = svcinfo.serviceVersion
        mutable_spec.vendorNameResourceKey = svcinfo.vendorNameResourceKey
        mutable_spec.vendorNameDefault = svcinfo.vendorNameDefault
        mutable_spec.serviceNameResourceKey = svcinfo.serviceNameResourceKey
        mutable_spec.serviceNameDefault = svcinfo.serviceNameDefault
        mutable_spec.serviceDescriptionResourceKey =\
            svcinfo.serviceDescriptionResourceKey
        mutable_spec.serviceDescriptionDefault =\
            svcinfo.serviceDescriptionDefault
        mutable_spec.serviceEndpoints = svcinfo.serviceEndpoints
        mutable_spec.serviceAttributes = svcinfo.serviceAttributes

    @staticmethod
    def _svcinfo_to_setspec(svcinfo):
        """
        Construct a set spec based on given svc info object.
        
        Args:
            svcinfo (ls spec): service info in LS API format
        """
        rereg_spec = lookup.ServiceRegistration.SetSpec()
        LookupServiceClient._copy_svcspec(svcinfo, rereg_spec)
        return rereg_spec

    def get_machine_id(self, svcinfo):
        """
        Helper function to get machine id of a service from LS service info.
        This exists because sadly the nodeId field of service info object
        doesn't hold the machine id, instead it is set to vmdir.ldu-guid.
        Instead the machine id is held in com.vmware.cis.cm.HostId key.
        
        Args:
            svcinfo (ls spec): service info in LS API format

        """
        for attr in svcinfo.serviceAttributes:
            if attr.key == 'com.vmware.cis.cm.HostId':
                return attr.value
        return None

### Transformation utilities ###
def _serviceAttribute2Dict(attr):
    """
    Transform utility for LS spec to dictionary and reverse
    """
    result = {
        "key" : attr.key,
        "value" : attr.value
    }
    return result

def _getSslCert(hostname,port):
    """
    Gets SSL cert from host on port specified.  Converts to
    string compatible with LS specs.
    
    Args:
        hostname (str): hostname
        port (int): port
    
    Returns:
        cert: certificate string formatted for lookup service endpoints
    """
    #  returns the cert trust value formatted for lstool
    logger.debug("Getting SSL certificate on %s:%s" % (hostname, port))
    socket.setdefaulttimeout(5)
    try:
        try:
            cert = ssl.get_server_certificate((hostname, port),ssl_version=ssl.PROTOCOL_TLS)
        
        except AttributeError:
            cert = ssl.get_server_certificate((hostname, port),ssl_version=ssl.PROTOCOL_SSLv23)

        except socket.timeout as e:
            raise Exception("Timed out getting certificate")

        except ConnectionRefusedError:
            # print("Connection refused while getting cert for host %s on port %s!" % (hostname, port))
            raise
        
        values = ['-----BEGIN CERTIFICATE-----','-----END CERTIFICATE-----','\n']
        
        for i in values:
            cert = cert.replace(i, '')
        logger.debug("Got certificate.")
        return cert

    except Exception as e:
        msg = ("[%s:%s]:%s" 
                        % (hostname, port, str(e)))
        raise Exception(msg)
        
def _dict2serviceAttribute(d):
    """
    Transform utility for LS spec to dictionary and reverse
    """
    attr = lookup.ServiceRegistration.Attribute()
    attr.key = d["key"]
    attr.value = d["value"]
    return attr

def _serviceType2Dict(serviceType):
    """
    Transform utility for LS spec to dictionary and reverse
    """
    result = {
        "product" : serviceType.product,
        "type" : serviceType.type
    }
    return result

def _dict2ServiceType(d):
    """
    Transform utility for LS spec to dictionary and reverse
    """
    svcType = lookup.ServiceRegistration.ServiceType()
    svcType.product = d['product']
    svcType.type = d['type']
    return svcType

def _serviceEndpoint2Dict(endpoint):
    """
    Transform utility for LS spec to dictionary and reverse
    """
    result = {
        "url" : endpoint.url,
        "sslTrust" : endpoint.sslTrust,
        "endpointType" : {
            "protocol" : endpoint.endpointType.protocol,
            "type" : endpoint.endpointType.type,
        },
        "endpointAttributes" : [_serviceAttribute2Dict(a) for a in endpoint.endpointAttributes]
    }
    return result

def _dict2ServiceEndpoint(d):
    """
    Transform utility for LS spec to dictionary and reverse
    """
    endpoint = lookup.ServiceRegistration.Endpoint()
    endpoint.url = d["url"]
    endpoint.sslTrust = d["sslTrust"]

    endpoint.endpointType = lookup.ServiceRegistration.EndpointType()
    endpoint.endpointType.protocol = d["endpointType"]["protocol"]
    endpoint.endpointType.type = d["endpointType"]["type"]

    endpoint.endpointAttributes = [_dict2serviceAttribute(a) for a in d["endpointAttributes"]]
    return endpoint

def _serviceInfo2Dict(serviceInfo):
    """
    Transform utility for LS spec to dictionary and reverse
    """
    result = {}
    for prop in SERVICE_INFO_PROPERTIES:
        result[prop] = getattr(serviceInfo, prop)

    result.update({
        "serviceEndpoints" : [_serviceEndpoint2Dict(e) for e in serviceInfo.serviceEndpoints],
        "serviceAttributes" : [_serviceAttribute2Dict(a) for a in serviceInfo.serviceAttributes],
        "serviceType" : _serviceType2Dict(serviceInfo.serviceType),
    })
    return result

def _dictToServiceCreateSpec(service):
    """
    Transform utility for LS spec to dictionary and reverse
    """
    create_spec = lookup.ServiceRegistration.CreateSpec()
    PRUNE_PROPERTIES = ["serviceId", "siteId"]

    for prop in SERVICE_INFO_PROPERTIES:
        if prop not in PRUNE_PROPERTIES:
            setattr(create_spec, prop, service[prop])

    create_spec.serviceEndpoints = [_dict2ServiceEndpoint(e) for e in service["serviceEndpoints"]]
    create_spec.serviceType  = _dict2ServiceType(service["serviceType"])
    create_spec.serviceAttributes = [_dict2serviceAttribute(a) for a in service["serviceAttributes"]]
    return create_spec

class LookupServiceClientHelper(object):
    """
    This class simplifies the interaction with the lookup service
    even further.  A wrapper for LookupServiceClient class
    
    Attributes:
        lsClient (LookupServiceClient object): connection to LS
        psc (str): FQDN of PSC
        ssoClient (SsoClient object): SSO client
    """
    def __init__(self, psc, username=None, password=None):
        """
        Args:
            psc (str): The PNID of the PSC we want to talk to
            username (None, optional): Admin username we will use to login
            password (None, optional): Password to the admin user
        """
        
        lookup_service_endpoint = "https://%s/lookupservice/sdk" % psc

        self.lsClient = LookupServiceClient(lookup_service_endpoint)
        self.ssoClient = None
        self.psc = psc

        if username or password:
            self.stsUrl, self.stsCertData = self.lsClient.get_sts_endpoint_data()
            ssoClientObj = SsoClient(self.stsUrl, self.stsCertData, username, password)
            self.lsClient.set_sso_client(ssoClientObj)
            try:
                sso.SsoAuthenticator(self.stsUrl).get_bearer_saml_assertion(username, password)
            except (sso.SoapException, Exception) as e:
                msg = 'Failed to validate sso credential. Error:\n%s\n\nExiting.' % e._fault_string
                logger.debug(msg)
                raise

    def _getHostId(self, svcInfoObjs):

        hostId = None
        for svcInfo in svcInfoObjs:
            hostId = self.lsClient.get_machine_id(svcInfo)
            if hostId is not None:
                break
        return hostId
    
    def getAll(self):
        """
        This will get all the service registrations in the SSO domain.
        This is done by providing an empty search_filter and calling 
        'get_service_info_list'.  Returns a dictionary of services.
        
        Returns:
            services: dictionary of services
        """

        logging.debug("Getting all services from LS.")
        search_filter = lookup.ServiceRegistration.Filter()
        svcInfoObjs = self.lsClient.get_service_info_list(search_filter=search_filter)
        # Transform the services to dictionary
        services = [_serviceInfo2Dict(s) for s in svcInfoObjs]
        return services
    
    def getPnid(self, pnid):
        """
        This method gets all services for a given PNID (or FQDN) by passing
        a 'pnid' value to get_service_info_list_ex.  Returns a dictionary of services,
        as well as the hostId detected.  hostId is to help us with finding services 
        that do not have a node ID.
        
        Args:
            pnid (str): primary network identifier (FQDN) we want to look for
        
        Returns:
            services, hostId: dictionary of services as well as the hostID
        """
        logging.debug("Getting all services from LS for PNID: %s." % pnid)
        svcInfoObjs = self.lsClient.get_service_info_list_ex(pnid=pnid)

        # Get first not none machineId as hostId
        hostId = self._getHostId(svcInfoObjs)
        # Transform the services to dictionary
        services = [_serviceInfo2Dict(s) for s in svcInfoObjs]
        return services, hostId

    def getNode(self, node):
        """
        This method searches for all services matching a particular LDU GUID
        aka "Node ID".  We pass a 'nodeId' filter to 'get_service_info_list'.
        Returns a dictionary of services.
        
        Args:
            node (str): the node ID or 'ldu guid' we are looking for.
        
        Returns:
            services: dictionary of filtered services
        """
        logging.debug("Getting all services from LS for node ID: %s" % node)
        search_filter = lookup.ServiceRegistration.Filter(nodeId=node)
        svcInfoObjs = self.lsClient.get_service_info_list(search_filter=search_filter)
        # Transform the services to dictionary
        services = [_serviceInfo2Dict(s) for s in svcInfoObjs]
        return services

    def getSite(self, site):
        """
        Allows us to get all services in a particular SSO site.
        Passes a filter with 'siteId' specified (site parameter passed to
        this function).  Returns dictionary of services.
        
        Args:
            site (str): the SSO site for which we want to return services.
        
        Returns:
            services: dictionary of filtered services
        """
        logging.debug("Getting all services from LS in Site: %s" % site)
        search_filter = lookup.ServiceRegistration.Filter(siteId=site)
        svcInfoObjs = self.lsClient.get_service_info_list(search_filter=search_filter)
        # Transform the services to dictionary
        services = [_serviceInfo2Dict(s) for s in svcInfoObjs]
        return services

    def unregisterServices(self, services):
        """
        Unregister all services for given VC in LookupService.
        Accepts a dictionary of services, then loops through the 
        service IDs and sends them to 'unregister_service'.
        
        Args:
            services (dict): Dictionary of services to unregister
        """
        for service in services:
            serviceId = service["serviceId"]
            self.lsClient.unregister_service(serviceId)
    
    def unregisterPnid(self, pnid):
        """
        Unregister all services for given VC in LookupService.  Sends 
        'pnid' parameter to 'get_service_info_list_ex', then loops through
        the returned dictionary and sends each service ID to 'unregister_service'

        Args:
            pnid (str): primary network identifier (FQDN) for which we want to
            unregister all services.
        """
        logging.debug("unregistering all services from LS for PNID: %s" % pnid)
        svcInfoObjs = self.lsClient.get_service_info_list_ex(pnid=pnid)
        if not svcInfoObjs:
            logger.info("No services to unregister")
            return

        for service in svcInfoObjs:
            svc_id = service.serviceId
            try:
                self.lsClient.unregister_service(svc_id)
                logger.info("Service %s has been successfully unregistered" % svc_id)
            except Exception:
                logger.error('Failed to unregister service %s.', svc_id)
    
    def register(self, svc_id, spec):
        """
        Accepts the service ID and dictionary formatted spec provided.  The
        spec is then converted from dictionary to API formatted spec.  Then,
        the service ID and API formatted spec are sent to 'register_service'

        Args:
            svc_id (str): This is the service ID of the service you want to register
            spec (dict): this is a dictionary formatted spec of the service
        """
        formatted_spec = _dictToServiceCreateSpec(spec)
        try:
            self.lsClient.register_service(svc_id, formatted_spec)
            logger.debug("Service %s has been successfully registered" % svc_id)
        except Exception:
            logger.error('Failed to register service %s.', svc_id)

    def unregister(self, svc_id):
        """
        Passes the provided service ID (svc_id) to 'unregister_service'.
        
        Args:
            svc_id (str): This is the service ID of the service you want to unregister
        """
        self.lsClient.unregister_service(svc_id)
        logger.debug("Service %s has been successfully unregistered" % svc_id)

    def registerServices(self, services):
        """
        Register given services in the LookupService.
        
        Args:
            services (TYPE): Dictionary of services to register
        
        """
        if not services:
            logger.info("No services to register")
            return

        for service in services:
            serviceId = service["serviceId"]
            createSpec = _dictToServiceCreateSpec(service)
            try:
                self.lsClient.register_service(serviceId, createSpec)
                logger.info("Service %s has been successfully registered", serviceId)
            except Exception:
                logger.error('Failed to register service %s.', serviceId)

    def reregister(self, pnid, services):
        """
        Unregister all existing services for given VC in LS and reregister
        the given services.  Unregisters all services for given PNID and 
        registers new ones based on the dictionary of services passed to it.

        Args:
            pnid (str): primary network identifier (FQDN) for which we want to
            unregister all services.
            services (str): dictionary of services we will register.
        """
        self.unregisterPnid(pnid)
        self.registerServices(services)

    def cleanup(self):

        if self.ssoClient:
            self.ssoClient.cleanup()

class get_params(object):
    """
    This returns a dictionary of the various parameters pertaining to
    the node on which this is run.  The parameters returned are:
    PNID, machine ID, ldu GUID, lookup service URL derived, the SSO site name,
    the PSC name, the SSL value from port 443, the hostname from hostname.txt,
    the SSO domain name (i.e. vsphere.local), OS type (windows or linux), 
    deployment type, and version/build number taken from rhttpproxy log.
    
    Attributes:
        params (dict): dictionary with all node specific details
    """
    def __init__(self):
        logger.debug("Getting node parameters")

        node_params = {}
        try:
            params = VmafdClient()
        except Exception as e:
            msg = "ERROR: VMAFD ISN'T STARTED"
            raise Exception(msg)

        
        try:
            with open(SSO_HOSTNAME_FILE) as fp:
                sso_hostname = fp.read()
        except:
            sso_hostname = ""

        try:
            node_params['ssltrust'] = _getSslCert(params.get_pnid(),443)
        except:
            node_params['ssltrust'] = "Failed to get certificate!"

        try:
            node_params['machineid'] = params.get_machine_id()
        except Exception as e:
            # print("Failed to get machine ID!  Exception was: %s" % e)
            node_params['machineid'] = "FAILED!"
            pass

        try:
            lsUrl = params.get_ls_location()
            psc = urlparse.urlparse(params.get_ls_location())
            node_params['pnid'] = params.get_pnid()
            node_params['lsurl'] = params.get_ls_location()
            node_params['siteid'] = params.get_site_name()
            node_params['psc'] = psc.hostname
            node_params['domain_name'] = params.get_domain_name()
        except:
            node_params['pnid'] = color_wrap("ERROR!",'fail')
            node_params['lsurl'] = color_wrap("ERROR!",'fail')
            node_params['siteid'] = color_wrap("ERROR!",'fail')
            node_params['psc'] = color_wrap("ERROR!",'fail')
            node_params['domain_name'] = color_wrap("ERROR!",'fail')
            # print("Parameters not available.  Is vmafdd running?")

        node_params['os_type'] = OS_TYPE
        node_params['lduid'] = params.get_node_id()
        node_params['sso_hostname'] = sso_hostname
        
        
        try:
            logger.debug("Getting deploy type")
            node_params['deploytype'] =  get_install_parameter('deployment.node.type', quiet=True)
        except:
            file = os.path.join(os.environ['VMWARE_CFG_DIR'],'deployment.node.type')
            with open(file) as fp:
                node_params['deploytype'] = fp.read()
        logger.debug("Getting build and version")
        path = os.path.join(get_cis_log_dir(), "rhttpproxy","*.log")
        list_files = glob.glob(path)
        latest = max(list_files, key=os.path.getctime)
        version, build = _getVersion()

        node_params['version'] = version
        node_params['build'] = build
        
        self.params = node_params
   
    def get(self):
        """
        Returns the parameters.
        
        Returns:
            dict: dictionary with all the parameters
        """
        logging.debug("Got parameters for this node (%s)" % self.params['pnid'])
        return self.params

def cli_path(cli_name):
    """
    Returns the absolute path of the specified CLI executable
    
    Args:
        cli_name (TYPE): Description
    
    Returns:
        str: path to the cli
    """
    component_dir = get_component_home_dir(def_by_os('vmafd', 'vmafdd'))
    cli_rel_path = def_by_os('bin/%s', '%s.exe') % cli_name
    return os.path.join(component_dir, cli_rel_path)

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
            return decode(item,encoding, errors='surrogateescape')
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
                    'ThumbprintSHA256': self.decode(self.x509.digest('sha256'),'ascii'),
                    'Version': self.x509.get_version(),
                    'SignatureAlg' : self.decode(self.x509.get_signature_algorithm(),'ascii'), 
                    'Issuer' :self.format_subject_issuer(self.x509.get_issuer()), 
                    'Valid From' : self.format_asn1_date(self.x509.get_notBefore()), 
                    'Valid Until' : self.format_asn1_date(self.x509.get_notAfter()),
                    'Subject' : self.format_subject_issuer(self.x509.get_subject())}
        combined = self.merge_cert(extension,certificate)

        cert_output = json.dumps(combined)

        return cert_output
  
    def __str__(self):
        """
        returns the certificate in string form if desired.
        """
        return self.cert()

class getCert(object):
    def __init__(self, cert, file=True):
        combined = json.loads(str(parseCert(cert,file=file).cert()))
        self.subjectAltName = combined.get('subjectAltName')
        self.subject = combined.get('Subject')
        self.validfrom = combined.get('Valid From')
        self.validuntil = combined.get('Valid Until')
        self.thumbprint = combined.get('Thumbprint')
        self.subjectkey = combined.get('subjectKeyIdentifier')
        self.authkey = combined.get('authorityKeyIdentifier')
        self.sha256 = combined.get('ThumbprintSHA256')
        self.combined = combined

class VecsStore(object):
    """
    Class for managing VECS store instances.  Wrapper for vecs-cli store functions.
    """
    def __init__(self):

        self._cli = cli_path('vecs-cli')

    def list(self):
        """
        Lists all VECS stores
        
        Returns:
            str: list of stores
        """
        cmd = [self._cli, 'store', 'list']
        try:
            result = invoke_command(cmd, quiet=True)
        except InvokeCommandException as ex:
            err = 'install.ciscommon.vecs.list.stores - Error in generating list of VECS store instances.'
            raise err
        return result.splitlines()

    def create(self, store_name):
        """
        Creates a VECS store with the specified name
        
        Args:
            store_name (str): name of the vecs store
        """
        cmd = [self._cli, 'store', 'create', '--name', store_name]
        try:
            invoke_command(cmd, quiet=True)
        except InvokeCommandException as ex:
            err = 'install.ciscommon.vecs.create.store - Error in creating VECS Store %s.' % store_name

            raise err

    def grantAccess(self, store_name, store_user, perm):
        '''
        Grant service user proper permissions to access VECS stores.
        '''
        cmd = [self._cli, 'store', 'permission']
        cmd += ['--name', store_name, '--user', store_user, '--grant', perm]
        try:
            invoke_command(cmd, stdin=self._password,
                           encoding=sys.getfilesystemencoding())
        except InvokeCommandException as ex:
            err = _T('install.ciscommon.vecs.grantAcess.acl',
                     'Error in granting permission %s for VECS Store %s.')
            raise ex

    def delete(self, store_name):
        """
        Delete VECS store with the specified name
        
        Args:
            store_name (str): name of the vecs store
        """
        cmd = [self._cli, 'store', 'delete', '--name', store_name]
        try:
            invoke_command(cmd, quiet=True)
        except InvokeCommandException as ex:
            err = 'install.ciscommon.vecs.delete.store - Error deleting VECS Store %s.' % store_name
            raise err

class VecsEntry(object):
    """
    Class for managing entries within a single VECS store.  Wrapper for vecs-cli entry functions
    """
    def __init__(self, store_name):
        """
        Constructor for managing the entries of the specified VECS store.
        
        Args:
            store_name (str): name of the vecs store
        """
        self._store_name = store_name
        self._cli = cli_path('vecs-cli')

    def list(self):
        """
        Lists the entries in the VECS store
        
        Returns:
            list: list of aliases
        """
        cmd = [self._cli, 'entry', 'list', '--store', self._store_name]
        try:
            result = invoke_command(cmd, quiet=True)
        except InvokeCommandException as ex:
            err = 'install.ciscommon.vecs.list.entries - Error in listing entries in VECS Store %s.' % self._store_name
            raise err
        # Just return the aliases
        lines = [l for l in result.splitlines() if l.startswith('Alias')]
        aliases = [l.split('\t')[1] for l in lines]
        return aliases

    def create(self, alias, cert_path, private_key_path):
        """
        Creates a new entry in the VECS store.
        
        Args:
            alias (str): alias of the cert
            cert_path (str): path to the cert file
            private_key_path (str): path to the key file
        """
        logging.debug("creating certificate %s in %s." % (alias, self._store_name))
        cmd = [self._cli, 'entry', 'create',
               '--store', self._store_name,
               '--alias', alias,
               '--cert', cert_path,
               '--key', private_key_path]
        try:
            invoke_command(cmd, quiet=True)
        except InvokeCommandException as ex:
            err = 'install.ciscommon.vecs.create.storeentry - Error in creating a new entry for %s in VECS Store %s.' % (alias, self._store_name)
            raise err

    def get_key(self, alias, output_file):
        """
        Get the private key of an entry in the VECS store
        
        Args:
            alias (str): alias of the cert
            output_file (str): Path to output file
        """
        logging.debug("Exporting key %s from %s to %s." % (alias, self._store_name, output_file))
        cmd = [self._cli, 'entry', 'getkey',
               '--store', self._store_name,
               '--alias', alias,
               '--output', output_file]
        try:
            invoke_command(cmd, quiet=True)
        except InvokeCommandException as ex:
            err = 'install.ciscommon.vecs.get.vecsentry - Error in retrieving private key for %s from VECS Store %s.'% (alias, self._store_name)
            raise err

    def get_cert(self, alias, output_file):
        """
        Export cert and key from an entry in the VECS store
        
        Args:
            alias (str): alias of the cert
            output_file (str): Path to output file
        """
        logging.debug("Exporting certificate %s from %s to %s." % (alias, self._store_name, output_file))
        cmd = [self._cli, 'entry', 'getcert',
                '--store', self._store_name,
                '--alias', alias,
                '--output',output_file]
        try:
            result = invoke_command(cmd, quiet=True)
            return result
        except InvokeCommandException as ex:
            err = 'install.ciscommon.vecs.get.certificate - Error in retrieving certificate for %s from VECS Store %s.'% (alias, self._store_name)
            logger.info(err)
            pass

    def delete(self, alias):
        """
        Deletes an entry in the VECS store
        
        Args:
            alias (str): alias of the cert
        """
        logging.debug("Deleting certificate %s from %s." % (alias, self._store_name))
        cmd = [self._cli, 'entry', 'delete',
               '-y',
               '--store', self._store_name,
               '--alias', alias]
        try:
            invoke_command(cmd, quiet=True)
        except InvokeCommandException as ex:
            err = 'install.ciscommon.vecs.delete.storeentry - Error in deleting entry %s from VECS Store %s.'% (alias, self._store_name)

            raise err

def getDeployType():
    file = os.path.join(os.environ['VMWARE_CFG_DIR'],'deployment.node.type')
    with open(file) as fp:
        result = fp.read()
    return result.strip()

def psqlQuery(query, return_all=False):
    logger.debug("running SQL query: %s" % query)
    psqlpath = "/opt/vmware/vpostgres/current/bin/psql"
    cmd = [psqlpath, '-d','VCDB', 'postgres', '-c', query]
    try:
        output, errors, timeout = Command(cmd).run()
        if return_all:
            return output
        else:
            output = output.split('\n')[2]
            return output.strip()
    except:
        msg = color_wrap("Requires vPostgres service!", 'fail')
        return msg

def sanitize_data(item, **kwargs):
    """
    Remove problematic characters from data
    :param item: data to process
    :type item: string or bytes object, list or dict
    :return: data suitable for printing as 'utf-8'
    :rtype: string
    All ANSI escapes, does not work on non-ansii escapes (use strict)
      re.compile(r'(\x9b|\x1b\[)[0-?]*[ -\/]*[@-~]')  # Includes colours
    Colours only
        re.compile(r'\x1b\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]') # Colours only
    Colours ok, all other escapes removed (above combined)
      re.compile(r'(?!\x1b\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K])((\x9b|\x1b\[)[0-?]*[ -\/]*[@-~])')
    Strict, only [a-zA-Z0-9] and common punctuation
        re.compile(r'[^\x20-\x7e]+')
    """
    if kwargs.get('strict', False):
        # Strict, only [a-zA-Z0-9] and common punctuation
        re_applied = re.compile(r'[^\x20-\x7e]+')
    elif kwargs.get('wizard', False):
        # Return only alphanumeric and '_'
        re_applied = re.compile(r'[^0-9a-zA-Z_]+')
        return re_applied.sub('', item)
    else:
        # Colours ok, all other escapes removed
        re_applied = re.compile(r'(?!\x1b\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K])((\x9b|\x1b\[)[0-?]*[ -/]*[@-~])')

    if isinstance(item, dict) or isinstance(item, list):
        return item
    if isinstance(item, bytes):
        item = item.decode('utf-8', 'ignore').strip()
    if isinstance(item, str):
        item = re_applied.sub('.', item)
        superfluous_newlines = re.compile(r'\n\s*\n')
        item = superfluous_newlines.sub('\n', item)
        return item
    else:
        return None