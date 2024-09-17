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

This class parses the lookup service information into human readable JSON.
Source data is either from the lstool.txt file found in the commands directory
of a PSC/embedded log bundle, or from a live system using the LS API.  It sorts
the information into a format/order that can be used to think about the SSO domain. 
"""

# -------------------------------------------------------------------------------
# Import universal python modules
# -------------------------------------------------------------------------------
import sys
import re
import os
import imp
from utils import *

# Import datetime
from datetime import datetime

# Import json
import json

# -------------------------------------------------------------------------------
# Import version specific python modules
# -------------------------------------------------------------------------------

# - URL Parser -
# The urlparse module is renamed to urllib.parse in Python 3. Thus, check for newer version first, if not found import from old version.
# No need to mark which module was imported, as old and new version have the same functionality.
try:
    from urllib.parse import urlparse as urlparse
except ImportError:
    from urlparse import urlparse as urlparse

# -------------------------------------------------------------------------------
# Import optional local modules
# -------------------------------------------------------------------------------

# - ParseCertificate -
# Requires: OpenSSL Python module
try:
    from parseCertificate import parseCert
    parseCertificate_module = True
except ImportError:
    parseCertificate_module = False

# -------------------------------------------------------------------------------
def parameters():
    """
    Get local node parameters from utils.get_params()
    
    Returns:
        dict: Returns local node parameters as dictionary
    """
    params = get_params()
    return params.get()

class LSTool_Parse(object):

  """
  This class parses the lookup service information into human readable JSON.
  
  Attributes:
      getData (json): data returned from utils.LookupServiceClientHelper.getAll()
      ls (LookupServiceClientHelper): intialized LookupServiceClientHelper object
      services (dict): variable holding the services for processing/output.
  """
  
  # This is the first parse.  gets rid of java output at the top, splits by service separator ----*
  def __init__(self):

    params = parameters()
    self.services = {}
    self.ls = LookupServiceClientHelper(params['psc'])
    self.getData = self.ls.getAll()

  # 
  def countField(self, rawdata, fieldSearch):
    """
    This is to give us the total number of endpoints found in the service.  We are looking for "Protocol"

    Args:
        rawdata (str): the endpoint being processed
        fieldSearch (str): Field to search for
    
    Returns:
        dict: dictionary of fields found
    """
    fieldCount = 0
    fields = {}
    endpointDetails = {}
    for line in rawdata.splitlines():
      if fieldSearch in line:
        line = line.split(": ",1)
        fieldCount += 1
        urlNumber = "URL(%s)" % str(fieldCount)
        endpointDetails[urlNumber] = line[1]
    label = "Endpoints (" + str(fieldCount) + ")"
    fields[label] = endpointDetails
    return fields

  def getField_ignore_localhost(self, rawdata, fieldSearch):
    """
    This grabs the "fields" we care about in each service.  We want to ignore 
    any field containing 'localhost'.  Otherwise, we get bad results (multiple nodes
    contain localhost)
    
    Args:
        rawdata (str): the endpoint being processed
        fieldSearch (str): Field to search for
    
    Returns:
        dict: dictionary of fields found
    """
    for line in rawdata.splitlines():
      fieldMatch = {}
      if fieldSearch in line:
        line = line.split(": ",1)
        fieldMatch[line[0]] = line[1]
        return fieldMatch

  def getField(self, rawdata, fieldSearch):
    """
    This grabs the "fields" we care about in each service.  We want to ignore 
    any field containing 'localhost'.  Otherwise, we get bad results (multiple nodes
    contain localhost)
    
    Args:
        rawdata (str): the endpoint being processed
        fieldSearch (str): Field to search for
    
    Returns:
        dict: dictionary of fields found
    """
    for line in rawdata.splitlines():
      fieldMatch = {}
      if fieldSearch in line:
        line = line.split(": ",1)
        if not "localhost" in line[1]:
          fieldMatch[line[0]] = line[1]
          return fieldMatch
          break
        else:
          continue

  def getEndpointCount(self,service):
    """
    Counts the number of endpoints for the given service.
    
    Args:
        service (dict): dictionary of service registration details
    
    Returns:
        dict: returns the number of endpoints appended to the service registration details.
    """
    fieldCount = 0
    fields = {}
    endpointDetails = {}
    for endpoint in service['serviceEndpoints']:
      fieldCount += 1
      urlNumber = "URL(%s)" % str(fieldCount)
      endpointDetails[urlNumber] = endpoint.get('url')
    label = "Endpoints (" + str(fieldCount) + ")"
    fields[label] = endpointDetails
    return fields

  def getEndpointTrust(self,service):
    """
    Gets the SSL trust value in the endpoints of the given service registration
    
    Args:
        service (dict): dictionary of service registration details
    
    Returns:
        dict: returns the SSL trust appended to the service registration details.
    """
    ssltrust = None
    for endpoint in service['serviceEndpoints']:
      if 'sslTrust' in endpoint.keys():
        ssltrust = endpoint['sslTrust']
        break
    return ssltrust

  def getServiceHostname(self, service):
    """
    Parses the hostname from the URL field of the given service registration.
    This is to organize the service registrations by to whom they belong.  We 
    want to avoid 'localhost' so that services don't end up in the wrong place.
    If no hostname is found, we put a place holder of "##NO_HOSTNAME##".
    
    Args:
        service (dict): dictionary of service registration details
    
    Returns:
        str: Returns the calculated hostname to interpret as owner of the service.
    """
    hostname = ""

    if service['serviceEndpoints']: 
        for endpoint in service['serviceEndpoints']:
            if 'url' in endpoint.keys():            
                parsed_url = urlparse(endpoint['url'])
                if parsed_url.hostname == 'localhost':
                    continue
                else:
                    hostname = parsed_url.hostname
    else:
        hostname = "##NO_HOSTNAME##"
    
    return hostname     
  # This is to mitigate the problems with formatting of cs.identity in 6.5.  
  # In 6.5, the endpoint has a new line every 64 characters or so.
  def convertData(self):
    """
    This is to mitigate the problems with formatting of cs.identity in 6.5.  
    In 6.5, the endpoint has a new line every 64 characters or so.
    
    Yields:
        str: formatted SSL trust value with no newlines
    """
    for x in self.getData:
      arraydata = ""
      for line in x.splitlines():
        if re.search(":",line):
          arraydata = arraydata + "##!" + line + "\n"
        else:
          arraydata = arraydata + line
      arraydata = arraydata.replace("\n", "")
      
      arraydata = arraydata.replace("##!","\n")
      yield arraydata

  # 
  
  def parseData(self, move_orphan_svcs=True):
    """
    This function builds the dictionary of all services from the lookup service.
    - Handles third party registrations that don't have a URL
    - Detects version of cs.identity to avoid flagging it as a duplicate (duplicates 
      are expected in systems upgraded from 6.0)
    - Builds dictionary by SSO site, then hostname, then service details

    Args:
        move_orphan_svcs (bool): Whether to move services orphaned under the
                                 "NO_HOSTNAME" node to a node with a sibling
                                 service with a matching Service ID

    Returns:
        dict: Returns entire SSO domain services sorted into human readable as a dictionary
    """
    for service in self.getData:
      serviceDetails = {}
      serviceCount = 0
      siteId = service.get('siteId')
      
      # Some third party registrations don't have URL.  We handle this here
      nodeName = self.getServiceHostname(service)
      serviceType = service['serviceType']['type']
      serviceId = {'Service ID' : service['serviceId']}
      nodeId = {'Node ID' : service['nodeId']}
      ownerId = {'Owner ID' : service['ownerId']}
      eVersion = {'Version' : service['serviceVersion']}
      endpointCount = self.getEndpointCount(service)
      endpointTrust = self.getEndpointTrust(service)

      # detect version of cs.identity to avoid flagging as duplicate
      
      if serviceType == 'cs.identity':
        for k in endpointCount.keys():
          if '6' in k:
            serviceType = serviceType + " (6.0)"
          elif '8' in k:
            serviceType = serviceType + " (6.5)"
          else:
            serviceType = serviceType + " Can't detect version!"

      # Check to make sure we have valid values.  Without it, we get errors for "NoneType"
      if all(v is not None for v in [serviceId, ownerId, eVersion, endpointCount]):
        serviceDetails.update(serviceId)
        if nodeId != None:
          serviceDetails.update(nodeId)
        serviceDetails.update(ownerId)
        serviceDetails.update(eVersion)
        serviceDetails.update(endpointCount)
        if endpointTrust != None and len(endpointTrust) > 0:
          try:
              pc = parseCert(str(endpointTrust[0]), file=False)
              stored_trust = {'SSL trust' : json.loads(str(pc))}
              serviceDetails.update(stored_trust)
          except Exception as e:
            print("Failed to parse certificate.  Error was: " + str(e))
            
          raw_trust = {'SSL trust (Raw)' : endpointTrust}
          serviceDetails.update(raw_trust)

      # Check if the various dictionaries exist.  Create if they don't, update if they do
      # This is important because python allows duplicate keys in dictionaries
      if not siteId in self.services:
        self.services[siteId] = {}
      if not nodeName in self.services[siteId]:
        self.services[siteId][nodeName] = {}
        self.services[siteId][nodeName]['Services'] = {}
        self.services[siteId][nodeName]['Services'][serviceType] = []
        self.services[siteId][nodeName]['Services'][serviceType].append(serviceDetails)
      else:          
        if not serviceType in self.services[siteId][nodeName]['Services']:
          self.services[siteId][nodeName]['Services'][serviceType] = []
          self.services[siteId][nodeName]['Services'][serviceType].append(serviceDetails)
        else:
          self.services[siteId][nodeName]['Services'][serviceType].append(serviceDetails)

    if move_orphan_svcs:
      self._move_orphan_services()

    return self.services

  def _move_orphan_services(self):
    # Find any services in the "NO_HOSTNAME" node (i.e. without node parents)
    # and move them to an appropriate parent node. The parent node is chosen
    # by selecting an arbitrary sibling service, such as 'vcenterserver', and
    # finding an instance of this service with the same Service ID as the
    # orphaned service. The orphan services will be moved to this sibling
    # service's parent node
    for site in self.services:
      # Used to remove empty "##NO_HOSTNAME##" trees. Need to use a flag here to
      # avoid changing the dict while looping through it.
      empty_flag = False
      for node in self.services[site]:
        if "##NO_HOSTNAME##" in node:
          remove_list = []
          for service in self.services[site][node]['Services'].keys():
            if self._add_to_sibling_service_node(
                    service, 'vcenterserver',
                    self.services[site][node]['Services'][service][0]):
              remove_list.append(service)
          if len(remove_list) > 1:
            for remove in remove_list:
              self.services[site][node]['Services'].pop(remove)

          if len(self.services[site][node]['Services']) < 1:
            empty_flag = True
          break
      if empty_flag:
        self.services[site].pop('##NO_HOSTNAME##')

    return self.services

  def _add_to_sibling_service_node(self, servicetype, sibling_servicetype,
                                   replace_service):
    # Find the 'sibling' of the specified service that has the same service ID
    # and add the specified service to that sibling's node in the services JSON
    repl_id = replace_service.get('Service ID')
    for site in self.services:
      for node in self.services[site]:
        if sibling_servicetype in self.services[site][node]['Services'].keys():
          vcid = self.services[site][node]['Services'][sibling_servicetype][0].get('Service ID')
          if vcid in repl_id:
            self.services[site][node]['Services'][servicetype] = [replace_service]
            return True
    return False

def main(args):
  """
  Main function.
  
  Args:
      args: Arguments passed on command line
  
  Returns:
      int: returns 0 (success)
  """
  lsJsonData = {}

  parser = LSTool_Parse()
  lsJsonData = parser.parseData()
  
  print(json.dumps(lsJsonData, sort_keys=True, indent=4))
  
  return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
