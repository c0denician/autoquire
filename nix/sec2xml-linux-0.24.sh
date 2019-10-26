#!/bin/bash

# SEC2XML v.0.24 - 29.05.2017
#
# Linux Security Configuration Report Generator
#
# Supported OS: Red Hat 5-7, SuSE 10-11, CentOS 5-7, Oracle Linux
#
# Copyright (c) 2006-2017 PT Nine Innovations. All rights reserved.
#
# Contact: info@9innovations.com
#
# THIS SCRIPT IS COPYRIGHTED. ANY USE OF THE SCRIPT, COPYING
# OF CODE IN FULL OR ANY PART OF THE CODE WITHOUT LICENSE IS
# A CRIME AND CAN BE PROSECUTED.
#

SCRIPT_VER="0.24"
SCRIPT_TITLE="Linux SEC2XML v."$SCRIPT_VER
SCRIPT_OS="Linux"

PROPERTIES_CREATOR_NAME=""
PROPERTIES_CREATOR_EMAIL=""
PROPERTIES_SUPERVISOR_NAME=""
PROPERTIES_SUPERVISOR_EMAIL=""
PROPERTIES_COMPANY=""
PROPERTIES_NOTE=""

SCRIPT_FILE_NAME=$(basename $0)

PATH=/bin:/sbin:/usr/bin/:/usr/sbin:$PATH
PATH_BIN="/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin"

#######
#######
# Initialising Script
#######
#######

### FUNCTIONS

function print_help () {
  echo $SCRIPT_TITLE
  echo ""
  echo "usage: $SCRIPT_FILE_NAME [parameters]"
cat <<'EOF'

Options:
  -h, --help             display this help information
  -V, --version          display program version
  -o, --output=STRING    define report output file
  -n, --cname=STRING     creator name
  -e, --cemail=STRING    creator e-mail
  -N, --sname=STRING     supervisor name
  -E, --semail=STRING    supervisor e-mail
  -C, --company=STRING   company
  -t, --note=STRING      note
  -g, --gzip             gzip output xml file
  -q, --quiet            quiet output
  -v, --verbose          verbose output

For support contact <support@itsecasia.com>.

EOF
}


function print_version() {
  echo $SCRIPT_TITLE
  echo ""
  exit
}


function resolve_symlink () {
  file="$1"
  if [ -x "${BIN_READLINK}" ]; then
	i=$($BIN_READLINK -f $file 2>/dev/null)
	echo "$i"
	return
  elif [ `stat --format=%N $file 2>/dev/null | grep '>' | wc -l | sed 's/^ *//g'` -gt 0 ]; then
    i=$(stat --format=%N $file 2>/dev/null | cut -d">" -f2 | cut -d"\`" -f2 | cut -d"‘" -f2 | cut -d"'" -f1 | cut -d "’" -f1)
    echo "$i"
    return
  else
    echo "$1"
    return
  fi
}


function print_test_info () {
  let T_ID=$T_ID+1
  /bin/echo "  [${T_ID}] $1"
}


function file_add () {

  T_PATH=$1
  T_MODE=$2

  if [ -h "${T_PATH}" ]; then

	T_SLSRC="$T_PATH"

	T_PATH="`resolve_symlink ${T_PATH}`"

	if [ -a "$T_SLSRC" ]; then
		t_exists="true"
	else
		t_exists="false"
	fi

	t_location=$(echo $T_PATH | sed 's%/[^/]*$%%')
	t_filename="`basename $T_PATH`"

	echo '<File Path="'${T_PATH}'" Name="'${t_filename}'" Exists="'${t_exists}'" Symbolic_link_src="'${T_SLSRC}'">' >> ${XML_REPORT_TMP}

  else 
	
	if [ -a "$T_PATH" ]; then
		t_exists="true"
	else
		t_exists="false"
	fi

	t_location=$(echo $T_PATH | sed 's%/[^/]*$%%')
	t_filename="`basename $T_PATH`"

	echo '<File Path="'${T_PATH}'" Name="'${t_filename}'" Exists="'${t_exists}'">' >> ${XML_REPORT_TMP}

  fi

  if [ "$T_MODE" = "all" -o "$T_MODE" = "info" ]; then

	  if [ -a "$T_PATH" ]; then

		  t_size=$( stat --format=%s $T_PATH )

		  t_la=$( stat --format=%x $T_PATH )
		  t_lm=$( stat --format=%y $T_PATH )
		  t_lc=$( stat --format=%z $T_PATH )

		  t_owner_username=$( stat --format=%U $T_PATH )
		  t_owner_uid=$( stat --format=%u $T_PATH )
		  t_owner_groupname=$( stat --format=%G $T_PATH )
		  t_owner_gid=$( stat --format=%g $T_PATH )

		  t_access_regular=$( stat --format=%A $T_PATH )
		  t_access_octal=$( stat --format=%a $T_PATH )

		  echo '<Size Size="'${t_size}'"/>' >> ${XML_REPORT_TMP}
		  echo '<Time LastAccess="'${t_la}'" LastModification="'${t_lm}'" LastChange="'${t_lc}'"/>' >> ${XML_REPORT_TMP}
		  echo '<Owner UserName="'${t_owner_username}'" UserId="'${t_owner_uid}'" GroupName="'${t_owner_groupname}'" GroupId="'${t_owner_gid}'"/>' >> ${XML_REPORT_TMP}
		  echo '<AccessRights Regular="'${t_access_regular}'" Octal="'${t_access_octal}'"/>' >> ${XML_REPORT_TMP}

		  if [ -n "$BIN_MD5SUM" -a -s "$T_PATH" ]; then
			t_md5sum=$( $BIN_MD5SUM $T_PATH 2>/dev/null | awk '{ print $1 }' )
			if [ -n "$t_md5sum" ]; then
				echo '<MD5Sum Checksum="'${t_md5sum}'"/>' >> ${XML_REPORT_TMP}
			fi
			t_md5sum=""
		  fi

	  fi
  fi

  if [ "$T_MODE" = "all" -o "$T_MODE" = "content" ]; then

	  if [ -a "$T_PATH" ]; then

		  t_size=$( stat --format=%s $T_PATH )

		  t_uub64=$( echo "TEST" | $BIN_UUENCODE -m - 2> /dev/null | grep "VEVTV" | wc -l | sed 's/^ *//g' )

		  if [ ${t_size} -gt 0 ]; then

			if [ ${t_uub64} -gt 0 ]; then
				  echo -n '<Content type="base64"><![CDATA[' >> ${XML_REPORT_TMP}
				  $BIN_UUENCODE -m $T_PATH - >> ${XML_REPORT_TMP}
				  echo ']]></Content>' >> ${XML_REPORT_TMP}
			else
				  echo -n '<Content><![CDATA[' >> ${XML_REPORT_TMP}
				  cat $T_PATH >> ${XML_REPORT_TMP}
				  echo ']]></Content>' >> ${XML_REPORT_TMP}
			fi

		  fi 

	  fi

  fi

  echo '</File>' >> ${XML_REPORT_TMP}
  
}


function directory_add () {

  T_PATH=$1
  T_MODE=$2

  if [ -h "${T_PATH}" ]; then

	T_SLSRC="$T_PATH"

	T_PATH="`resolve_symlink ${T_PATH}`"

	if [ -a "$T_PATH" ]; then
		t_exists="true"
	else
		t_exists="false"
	fi

	if [ -d "$T_PATH" ]; then
		t_isdirectory="true"
	else
		t_isdirectory="false"
	fi 

	t_location=$(echo $T_PATH | sed 's%/[^/]*$%%')
	t_filename="`basename $T_PATH`"

	echo '<Directory Path="'${T_PATH}'" IsDirectory="'${t_isdirectory}'" Exists="'${t_exists}'" Symbolic_link_src="'${T_SLSRC}'">' >> ${XML_REPORT_TMP} 

  else 
	
	if [ -a "$T_PATH" ]; then
		t_exists="true"
	else
		t_exists="false"
	fi

	if [ -d "$T_PATH" ]; then
		t_isdirectory="true"
	else
		t_isdirectory="false"
	fi 

	t_location=$(echo $T_PATH | sed 's%/[^/]*$%%')
	t_filename="`basename $T_PATH`"

	echo '<Directory Path="'${T_PATH}'" IsDirectory="'${t_isdirectory}'" Exists="'${t_exists}'">' >> ${XML_REPORT_TMP}

  fi

  if [ -a "$T_PATH" ]; then

	t_size=$( stat --format=%s $T_PATH )

	t_la=$( stat --format=%x $T_PATH )
	t_lm=$( stat --format=%y $T_PATH )
	t_lc=$( stat --format=%z $T_PATH )

	t_owner_username=$( stat --format=%U $T_PATH )
	t_owner_uid=$( stat --format=%u $T_PATH )
	t_owner_groupname=$( stat --format=%G $T_PATH )
	t_owner_gid=$( stat --format=%g $T_PATH )

	t_access_regular=$( stat --format=%A $T_PATH )
	t_access_octal=$( stat --format=%a $T_PATH )

	echo '<Time LastAccess="'${t_la}'" LastModification="'${t_lm}'" LastChange="'${t_lc}'"/>' >> ${XML_REPORT_TMP}
	echo '<Owner UserName="'${t_owner_username}'" UserId="'${t_owner_uid}'" GroupName="'${t_owner_groupname}'" GroupId="'${t_owner_gid}'"/>' >> ${XML_REPORT_TMP}
	echo '<AccessRights Regular="'${t_access_regular}'" Octal="'${t_access_octal}'"/>' >> ${XML_REPORT_TMP}

  fi

  if [ "$T_MODE" = "all" -o "$T_MODE" = "listing" ]; then

	echo -n '<ls><![CDATA[' >> ${XML_REPORT_TMP}
	ls -al $T_PATH 2>/dev/null >> ${XML_REPORT_TMP}
	echo ']]></ls>' >> ${XML_REPORT_TMP}

  fi

  echo '</Directory>' >> ${XML_REPORT_TMP} 
  
}


function get_binary_location () {
  RESULT=$1
  for PATH in $PATH_BIN; do
	if [ -x "${PATH}/${RESULT}" ]; then
		RESULT="$PATH/$RESULT"
	fi
  done
  echo "$RESULT"
}


#######
#######
# Initialization
#######
#######

OPT_GZIP=0

SHORTOPTS="o:n:e:N:E:C:t:hVgqv"
LONGOPTS="output:,cname:,cemail:,sname:,semail:,company:,note:,gzip,quiet,verbose,help,version"

if $(getopt -T >/dev/null 2>&1) ; [ $? = 4 ]; then
    OPTS=$(getopt --long $LONGOPTS -o $SHORTOPTS -n "$SCRIPT_FILE_NAME" -- "$@")
else
    case $1 in --help) print_help ; exit 0 ;; esac
    case $1 in --version) print_version ; exit 0 ;; esac
    OPTS=$(getopt $SHORTOPTS "$@")
fi

if [ $? -ne 0 ]; then
    echo "'$SCRIPT_FILE_NAME -h or --help' for more information" 1>&2
    exit 1
fi

while [ $# -gt 0 ]; do
   case $1 in
      -h|--help) print_help; exit 0;;
      -V|--version) print_version; exit 0;;
      -o|--output) OPT_OFILE=$2; shift 2;;
      -n|--cname) OPT_CNAME=$2; shift 2;;
      -e|--cemail) OPT_CEMAIL=$2; shift 2;;
      -N|--sname) OPT_SNAME=$2; shift 2;;
      -E|--semail) OPT_SEMAIL=$2; shift 2;;
      -C|--company) OPT_COMPANY=$2; shift 2;;
      -t|--note) OPT_NOTE=$2; shift 2;;
      -g|--gzip) OPT_GZIP=1; shift;;
      -q|--quiet) quiet=true; shift;;
      -v|--verbose) verbose=true; shift;;
      --) shift;break;;
       *) echo "Error: option processing error: $1" 1>&2; exit 1;;
   esac
done

if [ -n "$OPT_NOTE" ]; then
  PROPERTIES_NOTE=${OPT_NOTE}
fi

if [ -n "$OPT_CNAME" ]; then
  PROPERTIES_CREATOR_NAME=${OPT_CNAME}
fi

if [ -n "$OPT_CEMAIL" ]; then
  PROPERTIES_CREATOR_EMAIL=${OPT_CEMAIL}
fi

if [ -n "$OPT_SNAME" ]; then
  PROPERTIES_SUPERVISOR_NAME=${OPT_SNAME}
fi

if [ -n "$OPT_SEMAIL" ]; then
  PROPERTIES_SUPERVISOR_EMAIL=${OPT_SEMAIL}
fi

if [ -n "$OPT_COMPANY" ]; then
  PROPERTIES_COMPANY=${OPT_COMPANY}
fi

BIN_UNAME="`get_binary_location uname`"
BIN_DATE="`get_binary_location date`"
BIN_HOSTNAME="`get_binary_location hostname`"
BIN_UPTIME="`get_binary_location uptime`"
BIN_GREP="`get_binary_location grep`"
BIN_PS="`get_binary_location ps`"
BIN_FIND="`get_binary_location find`"
BIN_NETSTAT="`get_binary_location netstat`"
BIN_CHKCONFIG="`get_binary_location chkconfig`"
BIN_LSOF="`get_binary_location lsof`"
BIN_MD5SUM="`get_binary_location md5sum`"
BIN_IFCONFIG="`get_binary_location ifconfig`"
BIN_FREE="`get_binary_location free`"
BIN_LSPCI="`get_binary_location lspci`"
BIN_MOUNT="`get_binary_location mount`"
BIN_ROUTE="`get_binary_location route`"
BIN_HOSTID="`get_binary_location hostid`"
BIN_LSUSB="`get_binary_location lsusb`"
BIN_HWINFO="`get_binary_location hwinfo`"
BIN_RUNLEVEL="`get_binary_location runlevel`"
BIN_WHO="`get_binary_location who`"
BIN_LAST="`get_binary_location last`"
BIN_SYSCTL="`get_binary_location sysctl`"
BIN_LSMOD="`get_binary_location lsmod`"
BIN_MODINFO="`get_binary_location modinfo`"
BIN_MODPROBE="`get_binary_location modprobe`"
BIN_DF="`get_binary_location df`"
BIN_RPM="`get_binary_location rpm`"
BIN_YUM="`get_binary_location yum`"
BIN_DPKG="`get_binary_location dpkg`"
BIN_HDPARM="`get_binary_location hdparm`"
BIN_DEPMOD="`get_binary_location depmod`"
BIN_LSBRELEASE="`get_binary_location lsb_release`"
BIN_IPTABLES="`get_binary_location iptables`"
BIN_IPTABLESSAVE="`get_binary_location iptables-save`"
BIN_TR="`get_binary_location tr`"
BIN_SESTATUS="`get_binary_location sestatus`"
BIN_SORT="`get_binary_location sort`"
BIN_UUENCODE="`get_binary_location uuencode`"
BIN_READLINK="`get_binary_location readlink`"
BIN_GPG="`get_binary_location gpg`"
BIN_AUTHCONFIG="`get_binary_location authconfig`"

OS="`${BIN_UNAME}`"
OS_VER="`${BIN_UNAME} -sr`"
KERNEL="`${BIN_UNAME} -r`"

RH_RELEASE="`cat /etc/redhat-release 2>/dev/null`"
CENTOS_RELEASE="`cat /etc/centos-release 2>/dev/null`"
ORACLE_RELEASE="`cat /etc/oracle-release 2>/dev/null`"
UBUNTU_RELEASE="`cat /etc/lsb-release 2>/dev/null`"

if [ -x "${BIN_LSBRELEASE}" ]; then
	LSBREL_DISTRID=`${BIN_LSBRELEASE} -i | cut -f2`
	LSBREL_RELEASE=`${BIN_LSBRELEASE} -r | cut -f2`
	LSBREL_VERSION=`${BIN_LSBRELEASE} -c | cut -f2`
fi

DATE_START="`${BIN_DATE}`"
HOSTNAME="`${BIN_HOSTNAME}`"
HOSTID="`${BIN_HOSTID}`"
UPTIME="`${BIN_UPTIME}`"

MEM_TOTAL="`${BIN_FREE} | grep Mem | awk '{printf $2}'`"
MEM_USED="`${BIN_FREE} | grep Mem | awk '{printf $3}'`"
MEM_FREE="`${BIN_FREE} | grep Mem | awk '{printf $4}'`"

MEM_SWAP_TOTAL="`${BIN_FREE} | grep Mem | awk '{printf $2}'`"
MEM_SWAP_USED="`${BIN_FREE} | grep Mem | awk '{printf $3}'`"
MEM_SWAP_FREE="`${BIN_FREE} | grep Mem | awk '{printf $4}'`"

LOADAVG="`cat /proc/loadavg`"
RUNLEVEL="`${BIN_RUNLEVEL}`"

# The first three entries are the one, five, and fifteen minute load averages

DATESTAMP=`${BIN_DATE} +%Y%m%d`;
TIMESTAMP=`${BIN_DATE} +%H%M%S`;

XML_REPORT_FILE="sec2xml.linux.${HOSTNAME}.${DATESTAMP}.${TIMESTAMP}.xml"

if [ -n "${OPT_OFILE}" ]; then
 XML_REPORT_FILE=${OPT_OFILE}
 if [ -a ${XML_REPORT_FILE} ]; then
  echo "Error: File target report file \"${XML_REPORT_FILE}\" exists."
  exit 1
 fi
fi

XML_REPORT_TMP="tmp.sec2xml.report"

/bin/echo $SCRIPT_TITLE
/bin/echo ""
/bin/echo "     OS: "$OS_VER
if [ -n "$RH_RELEASE" ]; then
	/bin/echo " Red Hat: "$RH_RELEASE
fi
if [ -n "$CENTOS_RELEASE" ]; then
	/bin/echo " CentOS: "$CENTOS_RELEASE
fi
if [ -n "$ORACLE_RELEASE" ]; then
	/bin/echo " Oracle: "$ORACLE_RELEASE
fi
if [ -n "$LSBREL_DISTRID" ]; then
	/bin/echo " OS REL: ${LSBREL_DISTRID} ${LSBREL_RELEASE} ${LSBREL_VERSION}" 
fi
/bin/echo "   HOST: "$HOSTNAME
/bin/echo "   DATE: "$DATE_START
/bin/echo " UPTIME: "$UPTIME
/bin/echo ""

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root." 1>&2
   exit 1
fi

####### CLEAR TEMPORARY (OLD REPORTS) FILES

rm -rf ./tmp.sec2xml.* 2>/dev/null


#######
#######
# Data gathering
#######
#######

####### GENERAL CONFIG

print_test_info "Running chkconfig --list test"

if [ -x "${BIN_CHKCONFIG}" ]; then
	${BIN_CHKCONFIG} --list > tmp.sec2xml.chkconfig--list
fi

####### PROCESSES

print_test_info "Getting process information"

${BIN_PS} auxnwww --sort pid > tmp.sec2xml.ps

cat /proc/stat > tmp.sec2xml.procstat


####### USERS

print_test_info "Getting who and last logon information"

${BIN_WHO} -uH > tmp.sec2xml.who
${BIN_LAST} > tmp.sec2xml.last


####### NETWORK

print_test_info "Checking open TCP ports (netstat)"

${BIN_NETSTAT} -anp > tmp.sec2xml.netstat-anp

print_test_info "Checking open TCP ports (lsof)"

if [ -x "${BIN_LSOF}" ]; then
	${BIN_LSOF} -i TCP > tmp.sec2xml.lsof-tcp
fi

if [ -x "${BIN_LSOF}" ]; then
	${BIN_LSOF} -n -i TCP > tmp.sec2xml.lsofni-tcp
fi

print_test_info "Checking network interfaces (ifconfig)"

NET_INTERFACES=$(cat /proc/net/dev | ${BIN_GREP} -v Receive | ${BIN_GREP} : | cut -f1 -d:)

/bin/echo -n > tmp.sec2xml.ifconfig

for intf in ${NET_INTERFACES}; do
  echo -n '<ifconfig interface="'${intf}'"><![CDATA[' >> tmp.sec2xml.ifconfig
  ${BIN_IFCONFIG} -a ${intf} >> tmp.sec2xml.ifconfig
  echo ']]></ifconfig>' >> tmp.sec2xml.ifconfig
done

${BIN_ROUTE} -nv > tmp.sec2xml.route 2>/dev/null

if [ -x "${BIN_IPTABLES}" ]; then
	${BIN_IPTABLES} > tmp.sec2xml.iptableslist 2>/dev/null
fi

if [ -x "${BIN_IPTABLESSAVE}" ]; then
	${BIN_IPTABLESSAVE} > tmp.sec2xml.iptablessave 2>/dev/null
fi


####### FIND RELATED

print_test_info "Searching for none-zero .rhosts, .shosts and .netrc"

${BIN_FIND} / \( -name .rhosts -o -name .shosts -o -name .netrc \) -size +0 -exec ls -ldb {} \; > tmp.sec2xml.find-rhosts 2>/dev/null

print_test_info "Searching for files/directories without owner"

${BIN_FIND} / \( -nouser -o -nogroup \) -exec ls -ld {} \; > tmp.sec2xml.find-noowner 2>/dev/null

print_test_info "Searching for publicly writable files"

${BIN_FIND} / -perm -o+w \( -type d -o -type f \) -exec ls -ldb {} \; > tmp.sec2xml.find-pubwrite 2>/dev/null


####### SUID/SGID

print_test_info "Searching for suid/sgid files"

${BIN_FIND} / \( -perm -4000 -o -perm -2000 \) -type f -exec ls -ldn {} \; > tmp.sec2xml.find-suidall 2>/dev/null


####### EXTRA CHECKS

print_test_info "Exporting kernel configuration"

if [ -x "${BIN_SYSCTL}" ]; then
	${BIN_SYSCTL} -A 2>> sec2xml.err > tmp.sec2xml.sysctl
fi

print_test_info "Exporting kernel module configuration"

${BIN_LSMOD} | sed '1d' | while read line
do
	kmod_name=`echo $line | awk '{ print $1 }'`
	kmod_size=`echo $line | awk '{ print $2 }'`
	kmod_usedby=`echo $line | awk '{ print $3 }'`

	echo '<KernelModule Name="'${kmod_name}'" Size="'${kmod_size}'" UsedBy="'${kmod_usedby}'">' >> tmp.sec2xml.lsmod

	echo -n '<ModInfo><![CDATA[' >> tmp.sec2xml.lsmod
	${BIN_MODINFO} $kmod_name 2>&1 >> tmp.sec2xml.lsmod
	echo ']]></ModInfo>' >> tmp.sec2xml.lsmod

	echo '</KernelModule>' >> tmp.sec2xml.lsmod
done

${BIN_MODPROBE} -n -l -v > tmp.sec2xml.modprobe 2>/dev/null
${BIN_DEPMOD} -av > tmp.sec2xml.depmod 2>/dev/null

if [ -x "${BIN_AUTHCONFIG}" ]; then
	${BIN_AUTHCONFIG} --test > tmp.sec2xml.authconfig-test 2>/dev/null
fi

cat /proc/modules 2>/dev/null > tmp.sec2xml.procmodules 2>/dev/null

if [ -x "${BIN_SESTATUS}" ]; then
	${BIN_SESTATUS} > tmp.sec2xml.sestatus 2>/dev/null
fi

print_test_info "Exporting hardware configuration"

if [ -x "${BIN_LSPCI}" ]; then
	${BIN_LSPCI} > tmp.sec2xml.lspci 2>/dev/null
fi
if [ -x "${BIN_LSUSB}" ]; then
	${BIN_LSUSB} > tmp.sec2xml.lsusb 2>/dev/null
fi
if [ -x "${BIN_HWINFO}" ]; then
	${BIN_HWINFO} > tmp.sec2xml.hwinfo 2>/dev/null
fi

####### FILESYSTEM

${BIN_DF} > tmp.sec2xml.df
cat /proc/swaps > tmp.sec2xml.procswaps
${BIN_MOUNT} > tmp.sec2xml.mount
cat /proc/mounts > tmp.sec2xml.procmounts

DISKLIST=`/sbin/fdisk -l 2>/dev/null | grep "^/dev" | awk '{ print $1 }' | sed 's/[0-9]//g' | sort -u`

for DISK in $DISKLIST
do
	${BIN_HDPARM} -vIi $DISK > tmp.sec2xml.hdparm 2>/dev/null
done


####### SOFTWARE

print_test_info "Exporting software package info (yum/rpm)"

if [ -x "${BIN_RPM}" ]; then
	${BIN_RPM} -qa > tmp.sec2xml.rpm-qa 2>/dev/null
    ${BIN_RPM} -Va > tmp.sec2xml.rpm-Va 2>/dev/null
fi

if [ -x "${BIN_YUM}" ]; then
	${BIN_YUM} list installed > tmp.sec2xml.yumlistinstalled 2>/dev/null
	${BIN_YUM} info installed > tmp.sec2xml.yuminfoinstalled 2>/dev/null
	${BIN_YUM} check-update > tmp.sec2xml.check-update 2>/dev/null
	${BIN_YUM} --security check-update > tmp.sec2xml.security-check-update 2>/dev/null
	${BIN_YUM} updateinfo list --security > tmp.sec2xml.updateinfo_list_security 2>/dev/null
    ${BIN_YUM} verify-all > tmp.sec2xml.yumverifyall 2>/dev/null
fi

if [ -x "${BIN_DPKG}" ]; then
	${BIN_DPKG} -l > tmp.sec2xml.dpkginstalled 2>/dev/null
fi

if [ -x "${BIN_DPKG}" ]; then
	${BIN_DPKG} --get-selections > tmp.sec2xml.dpkgselections 2>/dev/null
fi

if [ -x "${BIN_GPG}" ]; then
	for i in `ls /etc/pki/rpm-gpg/*KEY* 2>/dev/null`; do echo "# $i" >> tmp.sec2xml.gpgkeys 2>/dev/null; ${BIN_GPG} --quiet --with-fingerprint $i >> tmp.sec2xml.gpgkeys 2>/dev/null ; done
fi


####### SSHD

if [ -x "${BIN_RPM}" ]; then
	SSHD_CONFIG_PATH="`$BIN_RPM -qcf /usr/sbin/sshd 2>/dev/null | grep -h sshd_config`"
fi

if [ ! -n "${SSHD_CONFIG_PATH}" ]; then
	if [ -a "/etc/ssh/sshd_config" ]; then
		SSHD_CONFIG_PATH="/etc/ssh/sshd_config"
	elif [ -a "/usr/local/etc/sshd_config" ]; then
		SSHD_CONFIG_PATH="/usr/local/etc/sshd_config"
	else
		SSHD_CONFIG_PATH=""
	fi
fi


####### MALWARE SEARCH

print_test_info "Searching for suspicious folders and files"	

${BIN_FIND} / -type d \( -name ".msf4*" -o -name ".ncrack*" -o -name ".zenmap*" -o -name ".x" -o -name ".s" -o -name ".u" -o -name ".p" -o -name ".q" -o -name ".r" -o -name sqlmap \) > tmp.sec2xml.malwaredirs 2>/dev/null
${BIN_FIND} / -type f \( -name "css.*p" -o -name "rs.*p" -o -name "reDuh*.*p" -o -name "dev.*p" -o -name "bcon.*" -o -name "tmp*.php" -o -name "tmp*.jsp" -o -name "css-win.*p" \) > tmp.sec2xml.malwarefiles 2>/dev/null

print_test_info "Searching for php backdoors"

${BIN_FIND} / -type f \( -name "*.php" \) -size +0 -exec ${BIN_GREP} -lE "((eval.*(base64_decode|gzinflate))|shell_exec|system|r57|k4mpr3t|c99|sh(3(ll|11)))" {} \; > tmp.sec2xml.phpbackdoors 2>/dev/null
${BIN_FIND} / -type f \( -name "*.jsp" \) -size +0 -exec ${BIN_GREP} -lE "(getRuntime|.exec\(|StreamConnector)" {} \; > tmp.sec2xml.jspbackdoors 2>/dev/null

print_test_info "Searching for other backdoors"

${BIN_GREP} -RPn "(passthru|shell_exec|system|phpinfo|base64_decode|chmod|mkdir|fopen|fclose|readfile) *\(" /var/www > tmp.sec2xml.backdoors 2>/dev/null

cat tmp.sec2xml.malwarefiles > tmp.sec2xml.malfiles
cat tmp.sec2xml.phpbackdoors >> tmp.sec2xml.malfiles
cat tmp.sec2xml.jspbackdoors >> tmp.sec2xml.malfiles
cat tmp.sec2xml.backdoors | awk -F":" '{print $1}' >> tmp.sec2xml.malfiles

### Finish time/date stamp

DATE_END=`${BIN_DATE}`


#######
#######
# Generating XML report
#######
#######

/bin/echo "Generating report ..."

### REPORT HEADER

cat << 'FILEEOF' > ${XML_REPORT_TMP}
<?xml version="1.0" encoding="iso-8859-1" standalone="yes"?>
<Report>
FILEEOF

### REPORT PROPERTIES

echo '<Properties>' >> ${XML_REPORT_TMP}

echo '<ScanDateTimeStamp Start="'${DATE_START}'" End="'${DATE_END}'"/>' >> ${XML_REPORT_TMP}
echo '<Script Version="'${SCRIPT_VER}'" Title="'${SCRIPT_TITLE}'" OS="'${SCRIPT_OS}'"/>' >> ${XML_REPORT_TMP}

echo '<Creator Name="'${PROPERTIES_CREATOR_NAME}'" Email="'${PROPERTIES_CREATOR_EMAIL}'"/>' >> ${XML_REPORT_TMP}
echo '<Supervisor Name="'${PROPERTIES_SUPERVISOR_NAME}'" Email="'${PROPERTIES_SUPERVISOR_EMAIL}'"/>' >> ${XML_REPORT_TMP}
echo '<Company Company="'${PROPERTIES_COMPANY}'"/>' >> ${XML_REPORT_TMP}
echo '<Description Description="''"/>' >> ${XML_REPORT_TMP}
echo '<InformationClassification InformationClassification="''"/>' >> ${XML_REPORT_TMP}
echo '</Properties>' >> ${XML_REPORT_TMP}


### REPORT DATA

echo '<Data>' >> ${XML_REPORT_TMP}


### BASIC DATA

echo '<BasicData>' >> ${XML_REPORT_TMP}
echo '<OS OS="'${OS}'" Title="'${OS_VER}'" Kernel="'${KERNEL}'" RHRel="'$RH_RELEASE'" CentOSRel="'$CENTOS_RELEASE'" OracleOSRel="'$ORACLE_RELEASE'" LSBRelDistrId="'$LSBREL_DISTRID'" LSBRelRelease="'$LSBREL_RELEASE'" LSBRelVersion="'$LSBREL_VERSION'" />' >> ${XML_REPORT_TMP}
echo '<Hostname Hostname="'${HOSTNAME}'"/>' >> ${XML_REPORT_TMP}
echo '<Hostid Hostid="'${HOSTID}'"/>' >> ${XML_REPORT_TMP}
echo '<UptimeString UptimeString="'${UPTIME}'"/>' >> ${XML_REPORT_TMP}
echo '<Memory Total="'${MEM_TOTAL}'" Used="'${MEM_USED}'" Free="'${MEM_FREE}'"/>' >> ${XML_REPORT_TMP}
echo '<MemorySwap Total="'${MEM_SWAP_TOTAL}'" Used="'${MEM_SWAP_USED}'" Free="'${MEM_SWAP_FREE}'"/>' >> ${XML_REPORT_TMP}
echo '<LoadAvg LoadAvg="'${LOADAVG}'"/>' >> ${XML_REPORT_TMP}
echo '<RunLevel RunLevel="'${RUNLEVEL}'"/>' >> ${XML_REPORT_TMP}

echo '<CPUs>' >> ${XML_REPORT_TMP}
oldIFS=$IFS
IFS="
"
for i in `cat /proc/cpuinfo | grep -E 'model name|cpu MHz'`; do
	if [ "`echo $i | grep 'model name' | wc -l | sed 's/^ *//g'`" -gt 0 ]; then
		CPU_MODEL="`echo $i | grep 'model name' | sed -e 's/^.*: //'`"
	else
		CPU_MHZ="`echo $i /proc/cpuinfo | grep 'cpu MHz' | head -1 | sed -e 's/^.*: //'`"
		echo '<CPU Model="'${CPU_MODEL}'" MHz="'${CPU_MHZ}'"/>' >> ${XML_REPORT_TMP}
		CPU_MODEL=""
		CPU_MHZ=""
	fi
done
IFS=$oldIFS
echo '</CPUs>' >> ${XML_REPORT_TMP}
echo '</BasicData>' >> ${XML_REPORT_TMP}


### USER ACTIVITIES

echo '<UserActivities>' >> ${XML_REPORT_TMP}

echo -n '<who><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.who 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></who>' >> ${XML_REPORT_TMP}

echo -n '<last><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.last 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></last>' >> ${XML_REPORT_TMP}

echo '</UserActivities>' >> ${XML_REPORT_TMP}


### FILESYSTEM

echo -n '<suidssgids><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.find-suidall 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></suidssgids>' >> ${XML_REPORT_TMP}

echo -n '<rhostsalike><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.find-rhosts 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></rhostsalike>' >> ${XML_REPORT_TMP}

echo -n '<fdnoowner><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.find-noowner 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></fdnoowner>' >> ${XML_REPORT_TMP}

echo -n '<fdpubwrite><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.find-pubwrite 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></fdpubwrite>' >> ${XML_REPORT_TMP}


### PROCESSES AND SOFTWARE

echo -n '<processes><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.ps 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></processes>' >> ${XML_REPORT_TMP}

echo -n '<procstat><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.procstat 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></procstat>' >> ${XML_REPORT_TMP}

echo -n '<rpm><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.rpm-qa 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></rpm>' >> ${XML_REPORT_TMP}

echo -n '<rpmVa><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.rpm-Va 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></rpmVa>' >> ${XML_REPORT_TMP}

echo -n '<yumlistinstalled><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.yumlistinstalled 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></yumlistinstalled>' >> ${XML_REPORT_TMP}

echo -n '<yuminfoinstalled><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.yuminfoinstalled 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></yuminfoinstalled>' >> ${XML_REPORT_TMP}

echo -n '<yumcheckupdate><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.check-update 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></yumcheckupdate>' >> ${XML_REPORT_TMP}

echo -n '<yumsecuritycheckupdate><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.security-check-update 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></yumsecuritycheckupdate>' >> ${XML_REPORT_TMP}

echo -n '<yumupdateinfolistsecurity><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.updateinfo_list_security 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></yumupdateinfolistsecurity>' >> ${XML_REPORT_TMP}

echo -n '<yumverifyall><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.yumverifyall 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></yumverifyall>' >> ${XML_REPORT_TMP}

echo -n '<dpkginstalled><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.dpkginstalled 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></dpkginstalled>' >> ${XML_REPORT_TMP}

echo -n '<dpkgselections><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.dpkgselections 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></dpkgselections>' >> ${XML_REPORT_TMP}


### NETWORKS

echo '<network>' >> ${XML_REPORT_TMP}

echo -n '<netstat><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.netstat-anp 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></netstat>' >> ${XML_REPORT_TMP}

echo -n '<lsof><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.lsof-tcp 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></lsof>' >> ${XML_REPORT_TMP}

echo -n '<lsofni><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.lsofni-tcp 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></lsofni>' >> ${XML_REPORT_TMP}

echo -n '<chkconfig><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.chkconfig--list 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></chkconfig>' >> ${XML_REPORT_TMP}

echo '<interfaces>' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.ifconfig 2>/dev/null >> ${XML_REPORT_TMP}
echo '</interfaces>' >> ${XML_REPORT_TMP}

echo -n '<route><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.route 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></route>' >> ${XML_REPORT_TMP}

echo -n '<iptableslist><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.iptableslist 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></iptableslist>' >> ${XML_REPORT_TMP}

echo -n '<iptablessave><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.iptablessave 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></iptablessave>' >> ${XML_REPORT_TMP}

echo '</network>' >> ${XML_REPORT_TMP}


### HARDWARE

echo '<hardware>' >> ${XML_REPORT_TMP}

echo -n '<lspci><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.lspci 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></lspci>' >> ${XML_REPORT_TMP}

echo -n '<lsusb><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.lsusb 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></lsusb>' >> ${XML_REPORT_TMP}

echo -n '<hwinfo><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.hwinfo 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></hwinfo>' >> ${XML_REPORT_TMP}

echo '</hardware>' >> ${XML_REPORT_TMP}


### EXTRAS

echo '<extras>' >> ${XML_REPORT_TMP}

echo -n '<sysctl><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.sysctl 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></sysctl>' >> ${XML_REPORT_TMP}

echo -n '<lsmod>' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.lsmod 2>/dev/null >> ${XML_REPORT_TMP}
echo '</lsmod>' >> ${XML_REPORT_TMP}

echo -n '<modprobe><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.modprobe 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></modprobe>' >> ${XML_REPORT_TMP}

echo -n '<procmodules><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.procmodules 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></procmodules>' >> ${XML_REPORT_TMP}

echo -n '<depmod><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.depmod 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></depmod>' >> ${XML_REPORT_TMP}

echo -n '<df><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.df 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></df>' >> ${XML_REPORT_TMP}

echo -n '<procswaps><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.procswaps 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></procswaps>' >> ${XML_REPORT_TMP}

echo -n '<mount><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.mount 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></mount>' >> ${XML_REPORT_TMP}

echo -n '<procmounts><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.procmounts 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></procmounts>' >> ${XML_REPORT_TMP}

echo -n '<hdparm><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.hdparm 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></hdparm>' >> ${XML_REPORT_TMP}

echo -n '<sestatus><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.sestatus 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></sestatus>' >> ${XML_REPORT_TMP}

echo -n '<gpgkeyscheck><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.gpgkeys 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></gpgkeyscheck>' >> ${XML_REPORT_TMP}

echo -n '<authconfigtest><![CDATA[' >> ${XML_REPORT_TMP}
cat tmp.sec2xml.authconfig-test 2>/dev/null >> ${XML_REPORT_TMP}
echo ']]></authconfigtest>' >> ${XML_REPORT_TMP}

echo '</extras>' >> ${XML_REPORT_TMP}

### FILES

echo "   exporting files ..."

echo '<files>' >> ${XML_REPORT_TMP}
file_add /boot/grub/grub.conf all
file_add /etc/SuSE-release all
file_add /etc/lsb-release all
file_add /etc/centos-release all
file_add /etc/oracle-release all
file_add /etc/at.allow all
file_add /etc/at.deny all
file_add /etc/bashrc all
file_add /etc/cron.allow all
file_add /etc/cron.deny all
file_add /etc/crontab all
file_add /etc/anacrontab all
file_add /etc/fstab all
file_add /etc/ftpusers all
file_add /etc/group all
file_add /etc/grub.conf all
file_add /etc/hosts all
file_add /etc/hosts.allow all
file_add /etc/hosts.deny all 
file_add /etc/hosts.equiv all
file_add /etc/httpd/conf/httpd.conf all
file_add /etc/inetd.conf all
file_add /etc/init.d/syslog all
file_add /etc/inittab all
file_add /etc/issue all
file_add /etc/issue.net all
file_add /etc/kernel-img.conf all
file_add /etc/kernel-pkg.conf all
file_add /etc/lilo.conf all
file_add /etc/login.defs all
file_add /etc/logrotate.conf all
file_add /etc/motd all
file_add /etc/ntp.conf all
file_add /etc/pam.conf all
file_add /etc/pam.d/common-password all
file_add /etc/pam.d/password-auth all
file_add /etc/pam.d/system-auth all
file_add /etc/passwd all
file_add /etc/securetty all
file_add /etc/selinux/config all
file_add /etc/shells all
file_add /etc/sudoers all
file_add /etc/sysctl.conf all
file_add /etc/syslog.conf all
file_add /etc/rsyslog.conf all
file_add /etc/syslog-ng/syslog-ng.conf all
file_add /etc/timezone all
file_add /etc/vsftpd/vsftpd.conf all
file_add /etc/xinetd.conf all
file_add /etc/yum.conf all
# audit
file_add /etc/audit/auditd.conf all
file_add /etc/audit/audit.rules all
# security
file_add /etc/security/limits.conf all
file_add /etc/security/opasswd all
file_add /etc/security/pwquality.conf all
# sysconfig
file_add /etc/sysconfig/amd all
file_add /etc/sysconfig/apmd all
file_add /etc/sysconfig/arpwatch all
file_add /etc/sysconfig/authconfig all
file_add /etc/sysconfig/autofs all
file_add /etc/sysconfig/boot all
file_add /etc/sysconfig/bootloader all
file_add /etc/sysconfig/clock all
file_add /etc/sysconfig/desktop all
file_add /etc/sysconfig/devlabel all
file_add /etc/sysconfig/dhcpd all
file_add /etc/sysconfig/exim all
file_add /etc/sysconfig/firewall all
file_add /etc/sysconfig/firstboot all
file_add /etc/sysconfig/gpm all
file_add /etc/sysconfig/harddisks all
file_add /etc/sysconfig/hwconf all
file_add /etc/sysconfig/i18n all
file_add /etc/sysconfig/init all
file_add /etc/sysconfig/ip6tables-config all
file_add /etc/sysconfig/ipchains all
file_add /etc/sysconfig/ipchains-config all
file_add /etc/sysconfig/iptables all
file_add /etc/sysconfig/irda all
file_add /etc/sysconfig/limits.conf all
file_add /etc/sysconfig/keyboard all
file_add /etc/sysconfig/kudzu all
file_add /etc/sysconfig/mouse all
file_add /etc/sysconfig/named all
file_add /etc/sysconfig/netdump all
file_add /etc/sysconfig/network all
file_add /etc/sysconfig/ntp all
file_add /etc/sysconfig/ntpd all
file_add /etc/sysconfig/pcmcia all
file_add /etc/sysconfig/radvd all
file_add /etc/sysconfig/rawdevices all
file_add /etc/sysconfig/samba all
file_add /etc/sysconfig/seccheck all
file_add /etc/sysconfig/security all
file_add /etc/sysconfig/selinux all
file_add /etc/sysconfig/sendmail all
file_add /etc/sysconfig/ssh all
file_add /etc/sysconfig/spamassassin all
file_add /etc/sysconfig/squid all
file_add /etc/sysconfig/suseconfig all
file_add /etc/sysconfig/syslog all
file_add /etc/sysconfig/system-config-securitylevel all
file_add /etc/sysconfig/system-config-users all
file_add /etc/sysconfig/system-logviewer all
file_add /etc/sysconfig/tux all
file_add /etc/sysconfig/ups all
file_add /etc/sysconfig/ulimit all
file_add /etc/sysconfig/yast2 all
file_add /etc/sysconfig/vncservers all
file_add /etc/sysconfig/xinetd all
file_add /bin/xterm all
file_add /lib/ld-ssl.so all
file_add /usr/share/svn/io.h all
file_add /var/log/yum.log all
# info only
file_add /etc/shadow info
file_add /etc/gshadow info
file_add /var/log/secure info
file_add /var/log/messages info
file_add /etc/ntp/keys info

for i in `cat /etc/passwd | awk -F":" '{print $6}' | sort -u`; do
	if [ -a "$i/.ssh/authorized_keys" ]; then file_add $i/.ssh/authorized_keys all; fi;
done

if [ -n "${SSHD_CONFIG_PATH}" ]; then
	file_add ${SSHD_CONFIG_PATH} all
fi

echo '</files>' >> ${XML_REPORT_TMP}

echo '<malfiles>' >> ${XML_REPORT_TMP}

for i in `cat tmp.sec2xml.malfiles | sort -u`; do
 file_add $i all
done

echo '</malfiles>' >> ${XML_REPORT_TMP}


echo "   exporting directories information ..."

echo '<directories>' >> ${XML_REPORT_TMP}
directory_add / listing
directory_add /etc listing
directory_add /etc/cron.d listing
directory_add /etc/init.d listing
directory_add /etc/ntp listing
directory_add /etc/pam.d listing
directory_add /etc/rc.d/init.d listing
directory_add /etc/sysconfig listing
directory_add /etc/xinetd.d listing
directory_add /home listing
directory_add /logs listing
directory_add /logs/app/Gateway/logs listing
directory_add /prd/ussdgw listing
directory_add /stack listing
directory_add /usr/nokia listing
directory_add /var/log listing
directory_add /var/run listing
directory_add /etc/cron.hourly listing
directory_add /etc/cron.daily listing
directory_add /etc/cron.weekly listing
directory_add /etc/cron.monthly listing
directory_add /var/lib/scr listing
directory_add /var/lib/sss listing
directory_add /var/lib/games listing
directory_add /var/lib listing
directory_add /usr/share/svn listing
directory_add /root/.msf4 listing

echo '</directories>' >> ${XML_REPORT_TMP}

echo '<maldirectories>' >> ${XML_REPORT_TMP}

for i in `cat tmp.sec2xml.malwaredirs | sort -u`; do
 directory_add $i listing
done

echo '</maldirectories>' >> ${XML_REPORT_TMP}

### REPORT DATA ENDED

echo '</Data>' >> ${XML_REPORT_TMP}


### REPORT FOOTER

cat << 'FILEEOF' >> ${XML_REPORT_TMP}
</Report>
FILEEOF


#######
#######
# PROCESSING FINAL REPORT
#######
#######

/bin/echo "Saving report(${XML_REPORT_FILE})."

${BIN_TR} -cd '["\t\r\n\f"][:print:]' < ${XML_REPORT_TMP} > ${XML_REPORT_FILE}

if [ ${OPT_GZIP} -eq 1 ]; then
  gzip ${XML_REPORT_FILE}
fi

/bin/echo -n > ${XML_REPORT_TMP}


#######
#######
# END OF XML REPORT
#######
#######


/bin/echo "Removing temporary files ..."

rm -rf ./tmp.sec2xml.* 2>/dev/null

/bin/echo "DONE."