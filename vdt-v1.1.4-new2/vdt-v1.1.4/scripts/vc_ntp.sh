#!/bin/sh
#__author__ = "Christopher Morrow"
#__credits__ = ["Keenan Matheny", "Christopher Morrow", "Fouad Sethna", "Kevin Hagopian"]
#__license__ = "SPDX-License-Identifier: MIT"
#__status__ = "Beta"
#__copyright__ = "Copyright (C) 2021 VMware, Inc.
#
#Permission is hereby granted, free of charge, to any person obtaining a copy of 
#this software and associated documentation files (the "Software"), to deal in the 
#Software without restriction, including without limitation the rights to use, 
#copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the 
#Software, and to permit persons to whom the Software is furnished to do so, 
#subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all 
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
#INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
#PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
#HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
#OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
#SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
__title__="VC NTP CHECK"
#
#This script tests if NTP is configured and running, then uses
#nptdate -q to query each server listed in /etc/ntp.conf.
#The output of ntpq -pn is shown last with a legend as reference.
#For explaination of ntpq output, see https://nlug.ml1.co.uk/2012/01/ntpq-p-output/831
#
#Setting color variables
# Reset
NC='\e[0m'       # Text Reset
# Regular Colors
Black='\e[0;30m'        # Black
Red='\e[0;31m'          # Red
Green='\e[0;32m'        # Green
Yellow='\e[0;33m'       # Yellow
Blue='\e[0;34m'         # Blue
Purple='\e[0;35m'       # Purple
Cyan='\e[0;36m'         # Cyan
White='\e[0;37m'        # White
BWhite='\e[1;37m'       # Bold White
BCyan='\e[1;36m'        # Bold Cyan
UL='\e[4m'              # Underline

ntplist=$(cat /etc/ntp.conf | grep server | awk '{print $2}')
ntprunning=$(systemctl status ntpd | grep "Active: " | awk '{print $2}')
vmtoolstime=$(/usr/bin/vmware-toolbox-cmd timesync status)
teststatus=0
testkb="https://kb.vmware.com/s/article/57146"

color_wrap() {
    if [ "$2" == "title" ]; then
        titlereplace='_'
        mystring="   $1   "
        echo -e "${UL}${BCyan}${mystring//?/_}\n$mystring${NC}"
    fi
    if [ "$2" == "subheading" ]; then
        echo -e "${BWhite}$1${NC}"
    fi
}
# color_wrap "VC NTP CHECK" "title"
echo ""

if [ ${vmtoolstime} == "Enabled" ]; then
  echo -e "${Yellow}[WARN]${NC} Time sync provided by ESXi host"
  teststatus=1
else
  if [ ${ntprunning} != "active" ]; then
    echo -e "${Red}[FAIL]${NC} NTP and Host time are both disabled!"
    echo ""
    teststatus=1
  exit 1
  else
    echo -e "${Green}[PASS]${NC} NTP service is running"
  fi
fi

if [ $teststatus -ne 0 ] ; then
        echo -e "${Red}[FAIL]${NC} NTP is not configured"
        echo -e "       Please see ${testkb}"
        echo -e "       Use the VAMI to configure NTP. NTP might need to be re-enabled on fresh installs"
        echo -e "       Once configured, synchronization may take several minutes"
        echo ""
        exit 1
fi

echo ""
color_wrap "NTP Server Check" "subheading"
echo ""
for ntp in $ntplist; do
  ntpdate -q ${ntp} > /dev/null 2>&1
  if [ $? -ne 0 ]; then
    echo -e "${Red}[FAIL]${NC} $ntp - no server suitable for synchronization found"
    teststatus=1
  else
    echo -e "${Green}[PASS]${NC} $ntp"
  fi
done
echo ""
color_wrap "NTP Status Check" "subheading"

echo -e "
+-----------------------------------${BWhite}LEGEND${NC}-----------------------------------+
| remote: NTP peer server                                                    |
| refid: server that this peer gets its time from                            |
| when: number of seconds passed since last response                         |
| poll: poll interval in seconds                                             |
| delay: round-trip delay to the peer in milliseconds                        |
| offset: time difference between the server and client in milliseconds      |
+-----------------------------------${BWhite}PREFIX${NC}-----------------------------------+
| * Synchronized to this peer                                                |
| # Almost synchronized to this peer                                         |
| + Peer selected for possible synchronization                               |
| – Peer is a candidate for selection                                        |
| ~ Peer is statically configured                                            |
+----------------------------------------------------------------------------+"
ntpq -pn

echo ""
if [[ $teststatus -ne 0 ]] ; then
    echo -e "RESULT: ${Red}[FAIL]${NC}"
    exit 1
else
    echo -e "RESULT: ${Green}[PASS]${NC}"
    exit 0
fi
