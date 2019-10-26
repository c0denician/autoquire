#!/bin/bash
#Auto Linux/Unix Acquisition tools
#ITSEC Asia (c) 2018
#contribute to c0denician
#Configuration
DIRCWD=`date '+%Y%m%d%H%M%S'`"_"`hostname`
ARCH=`uname -m`

#General
if [ `whoami` != "root" ];then
  echo "Error: Yor need root to run this script!"
  exit;
fi
mkdir ${DIRCWD}

#####
# sec2xml script execution
#####
echo "[+] Running sec2xml-linux"
chmod +x sec2xml-linux-0.24.sh
./sec2xml-linux-0.24.sh

#####
# spark-core execution
#####
echo "[+] Running spark-core"
if [ ${ARCH} == "x86_64" ]
then
  chmod +x ./spark-core/spark-core-linux-x64
  ./spark-core/spark-core-linux-x64
else
  chmod +x ./spark-core/spark-core-linux-x86
  ./spark-core/spark-core-linux-x86
fi

#####
# Acquiring directories
#####
echo "[+] Collecting etc directory"
tar cvfz ${DIRCWD}/etc.tar.gz /etc > /dev/null 2>&1
echo "[+] Collecting var log directory"
tar cvfz ${DIRCWD}/varlog.tar.gz /var/log > /dev/null 2>&1
echo "[+] Collecting boot directory"
tar cvfz ${DIRCWD}/boot.tar.gz /boot > /dev/null 2>&1


#####
# Acquire history files
#####
OIFS="$IFS"
IFS=$'\n'
for USER_SI in `cat /etc/passwd|grep sh$|awk -F : '{print $1}'`
do
  echo "[+] Collecting ${USER_SI} hostory file"
  HOMEDIR=`cat /etc/passwd|grep ^${USER_SI}|awk -F : '{print $6}'`
  tar cvfz ${DIRCWD}/${USER_SI}_history.tar.gz ${HOMEDIR}/.*history > /dev/null 2>&1
done

IFS="$OIFS"

##
