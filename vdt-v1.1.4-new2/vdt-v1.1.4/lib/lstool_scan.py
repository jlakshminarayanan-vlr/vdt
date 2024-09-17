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
  This tool processes the output from lstool_parse and attempts to 
  interpret the data into a general picture of the SSO domain from
  a topology standpoint.  It will try to identify the nodes (and node type)
  and solutions registered to the environment, as well as any common problems. 

"""

# -------------------------------------------------------------------------------
# Import universal python modules
# -------------------------------------------------------------------------------
import sys
import re
import os
import imp
from utils import _getSslCert,parseCert
import logging

# Import datetime
from datetime import datetime

# Import json
import json
logger = logging.getLogger(__name__)
# -------------------------------------------------------------------------------

class ErrorHandler(object):

  """
  Class to handle the problems found by the scanner.  Each error contains
  a description of the error, the severity, the recommend action, a link 
  to the KB for the issue, and the services affected by the error.
  """
  
  @staticmethod
  def ERROR_PORT_7444(err_data):
    """
    Reports error found when sso:sts, sso:groupcheck: and sso:admin have
    port 7444 in the URL of its endpoint.  This indicates stale 5.x data, 
    as we use port 443 in 6.0+.  This also likely means we have a stale 
    certificate in VECS under STS_INTERNAL_SSL_CERT.  Can cause problems with
    2nd and 3rd party solutions.
    
    Args:
        err_data (list): list of services affected by this problem.
    
    Returns:
        dict: Dictionary containing the error details
    """
    return {'Description': 'Port 7444 in Legacy SSO Service Registrations',
                      'Severity':'Medium',
                      'Recommended Action' : 'Please run python lsdoctor.py --stalefix option on this node.',
                      'Link' : 'https://kb.vmware.com/s/article/80469',
                      'Services with port 7444' : err_data}
  
  @staticmethod
  def STALE_55_USER(err_data):
    """
    This error shows any service with an owner ID from 5.x.  This service
    will need to be removed, as it is no longer needed.  Can cause problems
    with 2nd and 3rd party solutions.
    
    Args:
        err_data (list): list of services affected by this problem.
    
    Returns:
        dict: Dictionary containing the error details
    """
    return {'Description': 'Stale Service - 5.5 Solution User Found',
                      'Severity':'Medium',
                      'Recommended Action' : 'Please run python lsdoctor.py --stalefix option on this node.',
                      'Link':'https://kb.vmware.com/s/article/80469',
                      'Services to remove' : err_data}
  
  @staticmethod
  def STALE_55_USER_OK(err_data):
    """Summary
    
    Args:
        err_data (list): list of services affected by this problem.
    
    Returns:
        dict: Dictionary containing the error details
    """
    return {'Description': '5.5 Solution User Found, but functional.',
                      'Severity':'Medium',
                      'Recommended Action' : 'Please run python lsdoctor.py --stalefix option on this node.',
                      'Link':'https://kb.vmware.com/s/article/80469',
                      'Services that are okay' : err_data}
  
  @staticmethod
  def DUPLICATES_ERROR(err_data):
    """Summary
    
    Args:
        err_data (list): list of services affected by this problem.
    
    Returns:
        dict: Dictionary containing the error details
    """
    return {'Description': 'Duplicate Endpoints Detected',
                        'Severity':'High',
                        'Recommended Action': 'Ignore if this is the PSC HA VIP.  Otherwise, you must unregister the extra endpoints.',
                        'Link':'https://kb.vmware.com/s/article/80469',
                        'Duplicates by Node ID': err_data}
  
  @staticmethod
  def SSL_TRUST_MISMATCH(err_data):
    """Summary
    
    Args:
        err_data (list): list of services affected by this problem.
    
    Returns:
        dict: Dictionary containing the error details
    """
    return {'Description': 'SSL Trust Mismatch Detected',
                        'Severity':'High',
                        'Recommended Action': 'Please run python lsdoctor.py --trustfix option on this node.',
                        'Link':'https://kb.vmware.com/s/article/80469',
                        'Services grouped by SSL Trust': err_data}

  @staticmethod
  def SSL_TRUST_EXPIRED(err_data):
    """Summary
    
    Args:
        err_data (list): list of services affected by this problem.
    
    Returns:
        dict: Dictionary containing the error details
    """
    return {'Description': 'Certificate Expired',
                        'Severity':'High',
                        'Recommended Action': 'Regenerate the MACHINE_SSL_CERT.  If Legacy Endpoints, check STS_INTERNAL_SSL_CERT.',
                        'Link':'https://kb.vmware.com/s/article/2112283',
                        'link 2': 'https://kb.vmware.com/s/article/80469',
                        'Exp Dates by Thumbprint': err_data}
  @staticmethod
  def SSL_ERROR(hostname, port, err_data):
    """Summary
    
    Args:
        err_data (list): list of services affected by this problem.
    
    Returns:
        dict: Dictionary containing the error details
    """
    desc = 'SSL Error [%s:%s]: %s' % (hostname, port, err_data)
    return {'Description': desc,
                        'Severity':'High',
                        'Recommended Action': 'Investigate error: %s' %err_data}
# -------------------------------------------------------------------------------

class LSTool_Scan(object):

  """
  This class processes the output from lstool_parse and attempts to 
  interpret the data into a general picture of the SSO domain from
  a topology standpoint.  It will try to identify the nodes (and node type)
  and solutions registered to the environment, as well as any common problems. 
  
  Attributes:
      services (dict): Dictionary containing the services for an SSO domain.
  """
  
  #  
  def __init__(self, services):
    """
    Args:
        services (dict): Dictionary containing the services for an SSO domain.
    """
    # load the services data, instantiate 'Problems Detected' JSON tree
    self.services = services
    for site in self.services:
      for node in self.services[site]:
        self.services[site][node]['Problems Detected'] = {}
  
  def identifyNodes(self):
    """
    Identifies node type based on the presence of service registration types, or string in 
    owner ID. Will append the node type to the node name for quick identification.  
    See comments for the logic behind attempting to identify the nodes.
    """
    logger.debug("Identifying nodes")
    newservices = {}
    
    # service types to search for.  Includes multiple vectors for detection
    vcenter = ['vcenterserver', 'cs.inventory']
    psc = ['sso:sts','cs.identity','cs.license']
    cg = ['tokenservice','trustmanagement','hvc']
    standard = ['applmgmt','cis.vmonapi','sca','cs.vapi']
    pscha = ['sso:sts','sso:admin','sso:groupcheck','cs.identity (6.0)','cs.identity (6.5)','cs.license']

    for site in list(self.services.keys()):
      pscha_details = {}
      pscha_details['pscha_flag'] = False
      pscha_details['ha_members'] = []
      pscha_details['ha_vip'] = "" 
      
      for node in list(self.services[site].keys()):
        #ignore services with no hostname (3rd party)
        if "##NO_HOSTNAME##" not in node:
          temp_services = self.services[site][node]['Services'].keys()
          fixedtypes = []
          for name in temp_services:
            name = name.split(' (',1)[0]
            fixedtypes.append(name)
          
          # PSC HA configuration should have x each of cs.identity, cs.license,
          # sso:sts, sso:admin, and sso:groupcheck where x is the number
          # of PSCs behind the LB.  Each set will have the owner ID associated
          # to the PSC.  However, the URL for each endpoint will reflect the LB VIP.
          # The VIP will be the hostname, and we attempt to identify the members
          # based on the owner ID.  We go back through the PSCs in the site and
          # identify the members.
          if any(servicetype in fixedtypes for servicetype in psc):
            if not any(servicetype in fixedtypes for servicetype in standard):
              pscha_details['pscha_flag'] = True
              for servicetype in self.services[site][node]['Services'].keys():
                for i in range(len(self.services[site][node]['Services'][servicetype])):
                    member = self.services[site][node]['Services'][servicetype][i]['Owner ID'].split('@')[0]
                    if member not in pscha_details['ha_members']:
                      pscha_details['ha_members'].append(member)
                    if servicetype.split(' (',1)[0] in pscha:
                      owner = self.services[site][node]['Services'][servicetype][i].get('Owner ID').split('@')[0]
                      if owner != node:
                        pscha_details['ha_vip'] = node

      newservices[site] = {}
      
      for node in list(self.services[site].keys()):
        if "##NO_HOSTNAME##" not in node:
          orig_name = node
          new_name = orig_name
          
          # We can detect these node types:
          vcenter_flag = False
          psc_flag = False
          pscha_flag = False
          embedded_flag = False
          srm_flag = False
          vum_flag = False
          vr_flag = False
          sa_flag = False
          cg_flag = False

          # Detect and set flags

          # check for vCenter deployment type
          if any(servicetype in self.services[site][node]['Services'].keys() for servicetype in vcenter):
            vcenter_flag = True
          
          # check for PSC deployment type
          if any(servicetype in self.services[site][node]['Services'].keys() for servicetype in psc):
            psc_flag = True

          # if both VC and PSC detected, flag as embedded.          
          if vcenter_flag == True and psc_flag == True:
            embedded_flag = True

          # attempt to identify a cloud gateway appliance.
          if any(servicetype in self.services[site][node]['Services'].keys() for servicetype in cg):
            embedded_flag = False
            vcenter_flag = False
            psc_flag = False
            cg_flag = True
        
          # Support Assistant
          if 'com.vmware.phonehome.srservice' in self.services[site][node]['Services'].keys():
              sa_flag = True          
          
          #SRM/VR/VUM
          for service in self.services[site][node]['Services'].keys():
            for i in range(len(self.services[site][node]['Services'][service])):
                if 'vcDr' in service:
                  srm_flag = True
                if 'com.vmware.vcIntegrity' in service:
                  vum_flag = True
                if 'com.vmware.vcHms' in service:
                  vr_flag = True
                if 'com.vmware.vr' in self.services[site][node]['Services'][service][i].get("Owner ID"):
                  vr_flag = True
            
          
          # Translate flags to text, and append to node name.
          if srm_flag == True and vcenter_flag == False and cg_flag == False:
            new_name = node + " (SRM)"
          elif vum_flag == True and vcenter_flag == False and cg_flag == False:
            new_name = node + " (Update Manager)"
          elif vr_flag == True and vcenter_flag == False and cg_flag == False:
            new_name = node + " (vSphere Replication)"
          elif sa_flag == True and vcenter_flag == False and cg_flag == False:
            new_name = node + " (Support Assistant)"          
          elif embedded_flag == True:
            new_name = node + " (Embedded)"
          elif vcenter_flag == True:
            new_name = node + " (vCenter with external PSC)"
          elif psc_flag == True:
            new_name = node + " (External PSC)"
          elif cg_flag == True:
            new_name = node + " (VC 7.0 or CGW)"
          else:
            new_name = node + " (UNKNOWN)"

          if pscha_details['pscha_flag'] == True:
            if node in pscha_details['ha_members']:
              new_name = node + " (PSC HA Node Member)"
            if node in pscha_details['ha_vip']:
              new_name = node + " (PSC HA VIP)"

          newservices[site][new_name] = {}
          newservices[site][new_name]['Services'] = self.services[site][node]['Services'].copy()
          newservices[site][new_name]['Problems Detected'] = {}
        else:
          newservices[site][node] = self.services[site][node].copy()
    self.services = newservices
  
  def identifyProducts(self):
    """
    This function attempts to identify common 2nd party products 
    registered to the SSO domain.  Can detect SRM, NSX, Support Assistant
    and vROps
    """
    logger.debug("Identifying products used")

    #  Identifies the presence of products per VC
    products = []

    # Product mapping key/value pairs.  Quick to edit.
    productlist = {
                'vcDr': 'SRM',
                'vShield': 'NSX',
                'com.vmware.phonehome.srservice': 'Support Assistant',
                'com.vmware.vcops': 'vROps'
    }

    for site in list(self.services.keys()):
      for node in list(self.services[site].keys()):
        products = []
        self.services[site][node]['2nd Party Products'] = "None"   
        for service in list(self.services[site][node]['Services'].keys()):
          for servicetype,product in productlist.items():
            if servicetype in service:

              if product not in products:
                products.append(product)
        if len(products) > 0:
          self.services[site][node]['2nd Party Products'] = products

  def checkLegacy(self):
    """
    Performs checks for legacy SSO endpoints: sso:sts, sso:groupcheck, and sso:admin.
    Populates the results into services dictionary under 'PROBLEMS DETECTED'.
    
    - check for any endpoints including 7444.  If they exist, user should check for 
      STS_INTERNAL_SSL_CERT issue manually.

    - Check for entries that contain the 5.X web client solution user.  Recommend to use lstool unregister.

    """

    logger.debug("Performing legacy check")

    for site in list(self.services.keys()):
      
      for node in list(self.services[site].keys()):

        port7444problem = []
        stale55userproblem = []
        stale55userokproblem = []
        
        for service in list(self.services[site][node]['Services'].keys()):
          for i in range(len(self.services[site][node]['Services'][service])):
          
              issueFound = 'No problems found.'
              for field in list(self.services[site][node]['Services'][service][i].keys()):
                if 'Endpoints' in field:
                  for url in self.services[site][node]['Services'][service][i][field]:
                    
                    # check for any endpoints including 7444.  If they exist, user should check for STS_INTERNAL_SSL_CERT issue manually.
                    if '7444' in self.services[site][node]['Services'][service][i][field].get(url):                
                      issueFound = "Port 7444 detected!"
                      port7444problem.append(service)
              
              # Check for entries that contain the 5.X web client solution user.  Recommend to use lstool unregister.
              if self.services[site][node]['Services'][service][i]:
                if 'WebClient' in self.services[site][node]['Services'][service][i]['Owner ID']:
                  if "6.5" not in self.services[site][node]['Services'][service][i].get('Version'):
                    
                    issueFound = "5.5 Solution User Detected!"
                    stale55userproblem.append(service)
                  
                  else:           
                    issueFound = "5.5 Solution User Detected, but functional."
                    stale55userokproblem.append(service)
                
                self.services[site][node]['Services'][service][i].update( { 'Problems Detected':issueFound } )
        
        if len(port7444problem) > 0:
            self.services[site][node]['Problems Detected']['Port 7444 Found'] = ErrorHandler.ERROR_PORT_7444(port7444problem)
        if len(stale55userproblem) > 0:    
            self.services[site][node]['Problems Detected']['5.5 Solution User'] = ErrorHandler.STALE_55_USER(stale55userproblem)
        if len(stale55userokproblem) > 0:
            self.services[site][node]['Problems Detected']['5.5 Solution User OK'] = ErrorHandler.STALE_55_USER_OK(stale55userokproblem)

  def checkDuplicates(self):
    """
    Checks for duplicates of services.  If more than one occurrence of a service type
    has the same hostname in the URL, it is a duplicate.  We then attempt to list the
    duplicates sorted by node ID (unique on install).
    """
    logger.debug("Performing duplicate check")

    for site in self.services:
      for node in self.services[site]:
        duplicates = {}
        for service in self.services[site][node]['Services']:
          if len(self.services[site][node]['Services'][service]) > 1:
            for i in range(len(self.services[site][node]['Services'][service])):
                try:
                  nodeid = self.services[site][node]['Services'][service][i]['Node ID']
                except:
                  nodeid = "NONODEID"
                if not nodeid:
                  nodeid = "NO_NODE_ID"
                serviceid = self.services[site][node]['Services'][service][i]['Service ID']
                if nodeid not in duplicates:
                  duplicates.update({nodeid:{}})
                if service not in duplicates[nodeid]:
                  duplicates[nodeid].update({service : []})
                  duplicates[nodeid][service].append(serviceid)
                else:
                  duplicates[nodeid][service].append(serviceid)
              
        if len(duplicates) > 0:
          self.services[site][node]['Problems Detected']['Duplicates Found'] = ErrorHandler.DUPLICATES_ERROR(duplicates)
  
  def checkCerts(self):
    """
    This is the offline check.  For each node, checks whether or not all the ssl trust 
    values for the services are the same.  If there are differences, we flag this as an
    SSL trust mismatch detected.  We also check to ensure that the certificate (derived 
    from the ssl trust) is not expired.  Problems found are appended to "PROBLEMS_DETECTED".
    """
    logger.debug("Checking the certificate used.")


    today = datetime.now().strftime("%Y-%m-%d %H:%M:%S GMT")
    for site in self.services:
      for node in self.services[site]:
        thumbprints = {}
        thumbprint_services = []
        expired = {}
        
        for service in self.services[site][node]['Services']:
          for i in range(len(self.services[site][node]['Services'][service])):
              if 'SSL trust' not in self.services[site][node]['Services'][service][i]:
              
                  try:
                    if 'SSL trust (Raw)' in self.services[site][node]['Services'][service][i]:
                        raw_cert = self.services[site][node]['Services'][service][i]['SSL trust (Raw)']
                   
                        if raw_cert not in thumbprints:
                          thumbprints[raw_cert] = [service]
                        else:
                          thumbprints[raw_cert].append(service)
                  
                  except Exception as e:
                    logger.info("Failed to read raw certificate.  Error was: " + str(e))
                    
              else:
              
                  try:
                    service_thumbprint = self.services[site][node]['Services'][service][i]['SSL trust']['Thumbprint']
                    exp = self.services[site][node]['Services'][service][i]['SSL trust']['Valid Until']
                    
                    if exp <= today:
                      expired[service_thumbprint] = exp
                    
                    if service_thumbprint not in thumbprints:
                      thumbprints[service_thumbprint] = [service]
                    else:
                      thumbprints[service_thumbprint].append(service)
                  
                  except Exception as e:
                    logger.info("Failed to read certificate thumbprint and expiration.  Error was: " + str(e))
                
        if len(thumbprints.keys()) > 1:
            self.services[site][node]['Problems Detected']['SSL Trust Mismatch'] = ErrorHandler.SSL_TRUST_MISMATCH(thumbprints)
        if len(expired.keys()) > 0:
            self.services[site][node]['Problems Detected']['Certificate(s) Expired'] = ErrorHandler.SSL_TRUST_EXPIRED(expired)

  def live_checkCerts(self):
    """
    This is a check for a live system.  For each node, obtains the SSL certificate 
    presented on 443 of that node.  It will then compare this value with the ssl trust 
    value on the endpoints of each service.  If there are differences, we flag this as an
    SSL trust mismatch detected.  We also check to ensure that the certificate (derived 
    from the ssl trust) is not expired.  Problems found are appended to "PROBLEMS_DETECTED".
    """
    logger.info("Checking services for trust mismatches...")
    userwarning = False
    badtrust_count = 0
    host_blocklist = []
    today = datetime.now().strftime("%Y-%m-%d %H:%M:%S GMT")
    port = 443
    for site in self.services:
      for node in self.services[site]:
        if '##NO_HOSTNAME##' not in node:
          mismatched = {}
          expired = {}
          try:
            hostname = node.split()[0]
          except:
            continue
          if hostname in host_blocklist:
            continue
          try:
            cert = _getSslCert(hostname, port)
          except Exception as e:
            self.services[site][node]['Problems Detected']['SSL ERROR'] = ErrorHandler.SSL_ERROR(hostname,port,e)
            logger.debug("%s is blocklisted due to issues getting certificate.  Skipping this service." % hostname)
            host_blocklist.append(hostname)
            continue
          
          lc = json.loads(str(parseCert(cert, file=False)))
          lc_thumb = lc['Thumbprint']
          lc_exp = lc['Valid Until']
          
          if lc_exp <= today:
            logger.warning("Expired certificate found for node %s! " % hostname)
            expired[lc_thumb] = lc
   
          for service in self.services[site][node]['Services']:
            for i in range(len(self.services[site][node]['Services'][service])):
              if 'SSL trust (Raw)' in self.services[site][node]['Services'][service][i]:
                
                ep_trust = self.services[site][node]['Services'][service][i]['SSL trust (Raw)'][0].replace('\r\n','')
                ep_trust = ep_trust.replace('\n','')
                
                tc = json.loads(str(parseCert(ep_trust, file=False)))
                tc_thumb = tc.get('Thumbprint')
                tcexp = tc.get('Valid Until')
                
                if str(cert) != ep_trust:
                  if tc_thumb not in mismatched:
                    mismatched[tc_thumb] = [service]
                  else:
                    mismatched[tc_thumb].append(service)
          
          if len(mismatched.keys()) > 0:
            self.services[site][node]['Problems Detected']['SSL Trust Mismatch'] = ErrorHandler.SSL_TRUST_MISMATCH(mismatched)
          if len(expired.keys()) > 0:
            self.services[site][node]['Problems Detected']['Certificate(s) Expired'] = ErrorHandler.SSL_TRUST_EXPIRED(expired)
  
  def execute(self, live=False):
    """
    Executes the all the checks and returns the full report.
    
    Args:
        live (bool, optional): Flag on whether or not this is an offline check.
    
    Returns:
        dict: Sorted dictionary containing the results of the checks.
    """

    self.identifyNodes()
    self.checkLegacy()
    self.identifyProducts()
    self.checkDuplicates()

    if live == False:
      self.checkCerts()
    else:
      self.live_checkCerts()
    
    for site in self.services:
      for node in self.services[site]:
        if len(self.services[site][node]['Problems Detected'].keys()) < 1:
          self.services[site][node]['Problems Detected'] = "No problems found."
    
    return self.services          

# -------------------------------------------------------------------------------
# Main function.
# -------------------------------------------------------------------------------
def main(args, live=False):
  """
  Main function.
  
  Args:
      args (args): Arguments passed on command line
      live (bool, optional): Flag on whether or not this is an offline check.
  
  Returns:
      int: returns 0 for success.
  """
  in_filename = args[1]
  if in_filename is None:
    logger.info('Input file was not provided.')
    return 1
  
  # Create absolute path
  in_fileabspath = os.path.abspath(in_filename)
  
  # Load JSON from file
  with open(in_fileabspath) as json_file:
    lsJsonData = json.load(json_file)
  
  scanner = LSTool_Scan(lsJsonData)
  lsJsonData = scanner.execute()
  
  logger.info(json.dumps(lsJsonData, sort_keys=True, indent=4))
  
  return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
