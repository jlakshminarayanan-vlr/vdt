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
teststatus=0
testkb="https://kb.vmware.com/s/article/54682"
#######DNS########
fhs=$(hostname -f)
fhs=${fhs,,}
shs=$(hostname -s)
shs=${shs,,}
iphs=$(ifconfig eth0 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}')
nslist=$(cat /etc/resolv.conf  | grep -v '^#' | grep nameserver | awk '{print $2}' | sed ' /127\.0\.0\.1/ d')
hostsfilevami=$(cat /etc/hosts | grep -v '^#' | grep .)
hostsfile=$(cat /etc/hosts | sed '/VAMI_EDIT_BEGIN/,/VAMI_EDIT_END/{//!d}' | sed '/^#/d')
hostsarray=($hostsfile)
__title__="VC DNS CHECK"
# color_wrap "VC DNS CHECK" "title"
echo ""
echo "  NOTE:  If the script hangs here, it means none of the DNS servers are responding."
echo "         If this is the case, You should CTRL+C and investigate."
echo ""
color_wrap "Nameservers" "subheading"
echo "$nslist"
echo ""
color_wrap "Entries in /etc/hosts" "subheading"
echo "$hostsfilevami"
echo ""
color_wrap "Non-standard entries in /etc/hosts" "subheading"
nonstandardhostsfile=$(cat /etc/hosts | sed -n '/VAMI_EDIT_BEGIN/,/VAMI_EDIT_END/!p'| grep -v "#" | grep "\S")
if [ -z "$nonstandardhostsfile" ]
then
        echo -e " ${Green}[PASS]${NC} None"
else
    IFS=$'\n'
    for entry in $nonstandardhostsfile; do
        echo -e " ${Yellow}[WARN]${NC} $entry"
    done
fi
echo ""
#echo "$hostsfile"
if [[ -n $nonstandardhostsfile ]]; then
  color_wrap "Testing all non-standard entries with 'ping'..." "subheading"
  pingstatus=0
  for i in "${hostsarray[@]}"; do
    ping -c 1 -w 2 $i &> /dev/null
    if [ $? != 0 ]; then
      echo -e " ${Red}[FAIL]${NC} ${BWhite}$i${NC} is not pingable"
      pingstatus=1
      teststatus=1
    fi
  done
  if [[ pingstatus -eq 0 ]]; then
    echo -e " ${Green}[PASS]${NC}"
  fi
fi
echo ""

color_wrap "Basic Port Testing" "subheading"
for ns in $nslist; do
  nc -z -w 1 $ns 53
  if [ $? -ne 0 ]; then
    echo -e " ${Red}[FAIL]${NC} Port TCP 53 not open to nameserver $ns"
  else
    echo -e " ${Green}[PASS]${NC} Port TCP 53 open to nameserver $ns"
  fi
done
echo ""

color_wrap "Nameserver Queries" "subheading"
for ns in $nslist; do
  echo $ns
  forwardudp=$(dig +short $fhs @$ns)                                           #forward udp
  if [ "$forwardudp" != "$iphs" ]; then
    echo -e " ${Red}[FAIL]${NC} DNS with UDP - unable to resolve $fhs to $iphs "
    teststatus=1
  else
    echo -e " ${Green}[PASS]${NC} DNS with UDP - resolved $fhs to $iphs "
  fi
  reverseudp=$(dig +noall +answer -x $iphs @$ns | awk '{print $5}')         #reverse udp
  reverseudp=${reverseudp,,}
  if [ "$reverseudp" != "$fhs." ]; then
    echo -e " ${Red}[FAIL]${NC} Reverse DNS - unable to resolve $iphs to $fhs "
    teststatus=1
  else
    echo -e " ${Green}[PASS]${NC} Reverse DNS - resolved $iphs to $fhs"
  fi
  forwardtcp=$(dig +short +tcp $fhs @$ns)                                      #forward tcp

  if [ "$forwardtcp" != "$iphs" ]; then
    echo -e " ${Red}[FAIL]${NC} DNS with TCP - unable to resolve $fhs to $iphs"
    teststatus=1
  else
    echo -e " ${Green}[PASS]${NC} DNS with TCP - resolved $fhs to $iphs"
  fi
done

echo -e "\n Commands used: \n  dig +short <fqdn> <nameserver>\n  dig +noall +answer -x <ip> <namserver>\n  dig +short +tcp <fqdn> <nameserver>"

echo ""
if [[ $teststatus -ne 0 ]] ; then
    echo -e "RESULT: ${Red}[FAIL]${NC}"
    echo "Please see KB: $testkb"
    exit 1
else
    echo -e "RESULT: ${Green}[PASS]${NC}"
    exit 0
fi
