# VDT
 ```                                                    
VVVVVVVV           VVVVVVVVDDDDDDDDDDDDD       TTTTTTTTTTTTTTTTTTTTTTT
V::::::V           V::::::VD::::::::::::DDD    T:::::::::::::::::::::T
V::::::V           V::::::VD:::::::::::::::DD  T:::::::::::::::::::::T
V::::::V           V::::::VDDD:::::DDDDD:::::D T:::::TT:::::::TT:::::T
 V:::::V           V:::::V   D:::::D    D:::::DTTTTTT  T:::::T  TTTTTT
  V:::::V         V:::::V    D:::::D     D:::::D       T:::::T        
   V:::::V       V:::::V     D:::::D     D:::::D       T:::::T        
    V:::::V     V:::::V      D:::::D     D:::::D       T:::::T        
     V:::::V   V:::::V       D:::::D     D:::::D       T:::::T        
      V:::::V V:::::V        D:::::D     D:::::D       T:::::T        
       V:::::V:::::V         D:::::D     D:::::D       T:::::T        
        V:::::::::V          D:::::D    D:::::D        T:::::T        
         V:::::::V         DDD:::::DDDDD:::::D       TT:::::::TT      
          V:::::V          D:::::::::::::::DD        T:::::::::T      
           V:::V           D::::::::::::DDD          T:::::::::T      
            VVV            DDDDDDDDDDDDD             TTTTTTTTTTT      

                      vSphere Diagnostic Tool (Formerly Pulse)
```

__author__ = "Keenan Matheny"
__credits__ = ["Keenan Matheny", "Christopher Morrow", "Fouad Sethna", "Kevin Hagopian"]
__license__ = "SPDX-License-Identifier: MIT"
__version__ = "1.1.4"
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

Please send feedback / feature requests to project_pulse@vmware.com

=====================

v1.1.4 Release Notes:

VC Disk Space Check:
  -  Now ignores proc

VC vmdir Check:
  -  Fixed issue with special characters in password

VC Info Check:
  -  Reformatted output and added external PSC output

VC Core Check:
  -  Enhanced core file check


=====================

v1.1.3 Release Notes:

vdt.py:
  -  Fixed issue with encoding compatability in VC6.5

VC Cert Check:
  -  Fixed error when root cert has no key usage

=====================

v1.1.2 Release Notes:

House Keeping/General:
  -  Most tests timeout at 10 seconds by default.  Use -f to bypass timeouts
  -  Title of check now displays before it actually runs
  -  No longer causes problems when password contains certain special characters

VC Cert Check:
  -  Resolved issue encountered when cert contains non-ascii characters

=====================

v1.1.1 Release Notes:

VC AD Check:
  -  Now provides guidance when DNS check hangs

VC Cert Check:
  -  Removed output spew from KMS certs checks
  -  Now only verifies KMS algorithm and validity
  -  Solution user checks include extended key usage check
  -  Solution user checks include missing SAN
     -  This also fixes problems where the extension check
        failed to run

VC LS Check:
  -  Now throws a proper error when we fail to read the vpxd.cfg file


=====================

v1.1.0 Release Notes:

Main:
  -  Help menu added!  run: python vdt.py -h
  -  Interactive mode added.  Pauses after every test
  -  Script failures now log by default to the log file

VC Cert Check:
  -  Fixed issue causing false-positives for cert trust
  -  Better debug logging added


=====================

v1.0.9 Release Notes:

This is a bugfix release.

VC AD Check:
  -  forward/reverse DNS lookup is now case insensitive

VC Disk Check:
  -  Fixed bug where it wouldn't detect large files in the root of /storage/log

VC Cert Check:
  -  Now ignores KMS certificate store.  It is prone to false positives.
  -  Fixed issue where extensions wouldn't be checked under some circumstances
  -  Fixed issue where some self-signed certs were incorrectly flagged
     as untrusted because the subject key and auth key were the same

VC Syslog Check:
  -  Fixed problem with syslog server name resolution check


=====================

v1.0.8 Release Notes:

PROJECT PULSE IS NOW VDT (vSphere Diagnostic Tool)!

VC AD Check:
  -  Now does forward and reverse lookup on each DC

VC Disk Check:
  -  When disk space is low, it will show the top 5 largest directories
     and files

VC Cert Check:
  -  Now recommends delete of BACKUP_STORE
  -  Now checks ESXi Certificate Management Mode for 'thumbprint'

VC Syslog Check:
  -  Fixed a bug where half the check wasn't running

Misc:
  -  DNS check now runs after the info check

=====================

v1.0.7 Release Notes:

VC Info Check:
  -  Now throws failure on pnid/hostname mismatch with KB reference

VC Cert Check:

  -  No longer checks certs in KMS_ENCRYPTION for SAN and Trust
  -  CA check failure now includes caveat for VASA certs

Misc:
  -  Version, date, and log level now included at the top of the log

=====================

v1.0.6 Release Notes:

VC LS Check:
  -  There was a typo in the messaging for lsdoctor, changed it
     from 'ls_doctor' to 'lsdoctor'

VC vmdir Check:
  -  Removed extra quotation mark at the beginning of the arguments
     message.

VC Cert Check:
  -  No longer checks entries with '##NO_HOSTNAME##'
  -  Fixed messaging on cert expiration failure.  It was sort of 
     redundant
  -  No longer checks the APPLMGMT_PASSWORD vecs store
  -  No longer checks WCP cert store for SAN consistency
  -  Now checks all certs in SMS store even if the alias' contain
     forward slashes (like vasa providers).  Does not check these
     for trust or SAN consistency by design.


=====================

v1.0.5 Release Notes:

VC DNS Check:
  -  Resolved issue with DNS resolution and upper/lower case
  -  Now checks for non-standard/manual entries in /etc/hosts

VC Cert Check:
  -  Fixed issue where trust chain was incorrectly flagged as missing
  -  Now checks all certificates/certificate stores
  -  Now checks for an alerts on a SHA1 signature algorithm


=====================

v1.0.4 Release Notes:

VC VMdir Check (New!):
  -  Moved partner status from vc information to this check
  -  Checks partner availability
  -  Checks for startup arguments for vmdir containing 'standalone'
  -  Checks vmdir 'State' value and alerts on anything but 'Normal'

VC DB Check (New!):
  -  Checks top 10 largest tables
  -  Checks DB size on disk
  -  Checks DB size according to Postgres

VC Info:
  -  Now displays any disabled plugins

VC Cert Check:
  -  Added certificate check for eam, rbd, and imagebuilder extensions


=====================

v1.0.3 Release Notes:

LS check:
	-  Added a 5 timeout when getting certs for nodes.  Should fix issues with the script hanging for a very long time
	-  Added check for orphaned/3rd party services with appropriate messaging
	-  Fixed issue with the check incorrectly identifying the node type.
	
VC Cert Check:
	-  Added additional information regarding signing chains.  We now show which CAs signed which certs for the local node.
