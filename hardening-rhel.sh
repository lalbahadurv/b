#!/bin/sh
#server=`ifconfig | awk -F':' '/inet addr/&&!/127.0.0.1/{split($2,_," ");print _[1]}' | grep -v virbr`
#HARD_LOG="/var/log//root/Desktop/BackupB4Hardening_hard_log"

mkdir -p /root/Desktop/BackupB4Hardening/

/bin/echo "Creating Directory /root/Desktop/BackupB4Hardening for Backup of critical files"
/bin/echo "Creating Directory /root/Desktop/BackupB4Hardening for Backup of critical files" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 2

/bin/echo "mkdir /root/Desktop/BackupB4Hardening" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 2
echo "Directory /root/Desktop/BackupB4Hardening created." >> /root/Desktop/BackupB4Hardening/output.txt
echo "Directory /root/Desktop/BackupB4Hardening created."
sleep 2
/bin/echo "######################################################"
/bin/echo "Backup for system files is in progress , it may take few seconds ...!!!"
sleep 3
/bin/echo "tar -zcvf /root/Desktop/BackupB4Hardening/etc.tar.gz /etc /boot" >> /root/Desktop/BackupB4Hardening/output.txt
/bin/echo "tar -zcvf /root/Desktop/BackupB4Hardening/etc.tar.gz /etc /boot" 
sleep 2
tar -zcvf /root/Desktop/BackupB4Hardening/osbackup.tar.gz /etc /boot 2> /root/Desktop/BackupB4Hardening/output.txt1
sleep 40
if [ $? -eq 0 ]; then  /bin/echo "Files have been copied to /root/Desktop/BackupB4Hardening directory " >> /root/Desktop/BackupB4Hardening/output.txt ; 
else /bin/echo /bin/echo -e "\n" >> /root/Desktop/BackupB4Hardening/output.txt ; fi

echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################"
sleep 3
echo -e "Taking Backups of Following Files"
echo -e "Taking Backups of Following Files" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "/etc/sysctl.conf
/etc/resolv.conf
/etc/yum.repos.d/client.repo
/etc/ntp.conf
/etc/security/limits.conf
/etc/rsyslog.conf
/etc/cron.deny
/etc/at.deny
/etc/pam.d/su
/root/.bash_profile
/etc/bashrc
/etc/init.d/functions
/etc/login.defs
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/issue.net
/etc/inittab
/etc/motd
/etc/issue
/etc/fstab
/etc/pam.d/system-auth-ac
/boot/grub/grub.conf
/etc/passwd
/etc/securetty"
echo -e "/etc/sysctl.conf
/etc/resolv.conf
/etc/yum.repos.d/client.repo
/etc/ntp.conf
/etc/security/limits.conf
/etc/rsyslog.conf
/etc/cron.deny
/etc/at.deny
/etc/pam.d/su
/root/.bash_profile
/etc/bashrc
/etc/init.d/functions
/etc/login.defs
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/issue.net
/etc/inittab
/etc/motd
/etc/issue
/etc/fstab
/etc/pam.d/system-auth-ac
/boot/grub/grub.conf
/etc/passwd
/etc/securetty" >> /root/Desktop/BackupB4Hardening/output.txt


echo "cp -rfp /etc/sysctl.conf /root/Desktop/BackupB4Hardening/sysctl.conf
cp -rpf /etc/resolv.conf /root/Desktop/BackupB4Hardening/resolv.conf
cp -rpf /etc/yum.repos.d/client.repo /root/Desktop/BackupB4Hardening/client.repo
cp -rpf /etc/ntp.conf /root/Desktop/BackupB4Hardening/ntp.conf
cp -rpf /etc/security/limits.conf /root/Desktop/BackupB4Hardening/limits.conf
cp -rfp /etc/rsyslog.conf /root/Desktop/BackupB4Hardening/rsyslog.conf
cp -rfp /etc/cron.deny /root/Desktop/BackupB4Hardening/cron.deny
cp -rfp /etc/at.deny /root/Desktop/BackupB4Hardening/at.deny
cp -rfp /etc/pam.d/su  /root/Desktop/BackupB4Hardening/su
cp -rfp /root/.bash_profile /root/Desktop/BackupB4Hardening/.bash_profile
cp -rfp /etc/bashrc /root/Desktop/BackupB4Hardening/bashrc
cp -rfp /etc/init.d/functions /root/Desktop/BackupB4Hardening/functions
cp -rfp /etc/login.defs /root/Desktop/BackupB4Hardening/login.defs
cp -rfp /etc/ssh/ssh_config /root/Desktop/BackupB4Hardening/ssh_config
cp -rfp /etc/ssh/sshd_config /root/Desktop/BackupB4Hardening/sshd_config
cp -rfp /etc/issue.net /root/Desktop/BackupB4Hardening/issue.net
cp -rfp /etc/inittab /root/Desktop/BackupB4Hardening/inittab
cp -rfp /etc/motd /root/Desktop/BackupB4Hardening/motd
cp -rfp /etc/issue /root/Desktop/BackupB4Hardening/issue
cp -rfp /etc/fstab /root/Desktop/BackupB4Hardening/fstab
cp -rfp /etc/pam.d/system-auth-ac /root/Desktop/BackupB4Hardening/system-auth-ac
cp -rfp /boot/grub/grub.conf /root/Desktop/BackupB4Hardening/grub.conf
cp -rfp /etc/passwd /root/Desktop/BackupB4Hardening/passwd
cp -rfp /etc/securetty /root/Desktop/BackupB4Hardening/securetty" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 1
cp -rfp /etc/sysctl.conf /root/Desktop/BackupB4Hardening/sysctl.conf
cp -rpf /etc/resolv.conf /root/Desktop/BackupB4Hardening/resolv.conf
cp -rpf /etc/yum.repos.d/client.repo /root/Desktop/BackupB4Hardening/client.repo
cp -rpf /etc/ntp.conf /root/Desktop/BackupB4Hardening/ntp.conf
cp -rpf /etc/security/limits.conf /root/Desktop/BackupB4Hardening/limits.conf
cp -rfp /etc/rsyslog.conf /root/Desktop/BackupB4Hardening/rsyslog.conf
cp -rfp /etc/at.deny /root/Desktop/BackupB4Hardening/at.deny
cp -rfp /etc/cron.deny /root/Desktop/BackupB4Hardening/cron.deny
cp -rfp /etc/pam.d/su  /root/Desktop/BackupB4Hardening/su
cp -rfp /root/.bash_profile /root/Desktop/BackupB4Hardening/.bash_profile
cp -rfp /etc/bashrc /root/Desktop/BackupB4Hardening/bashrc
cp -rfp /etc/init.d/functions /root/Desktop/BackupB4Hardening/functions
cp -rfp /etc/login.defs /root/Desktop/BackupB4Hardening/login.defs
cp -rfp /etc/ssh/ssh_config /root/Desktop/BackupB4Hardening/ssh_config
cp -rfp /etc/ssh/sshd_config /root/Desktop/BackupB4Hardening/sshd_config
cp -rfp /etc/issue.net /root/Desktop/BackupB4Hardening/issue.net
cp -rfp /etc/motd /root/Desktop/BackupB4Hardening/motd
cp -rfp /etc/issue /root/Desktop/BackupB4Hardening/issue
cp -rfp /etc/pam.d/system-auth-ac /root/Desktop/BackupB4Hardening/system-auth-ac
cp -rfp /boot/grub/grub.conf /root/Desktop/BackupB4Hardening/grub.conf
cp -rfp /etc/securetty /root/Desktop/BackupB4Hardening/securetty
cp -rfp /etc/fstab /root/Desktop/BackupB4Hardening/fstab
cp -rfp /etc/passwd /root/Desktop/BackupB4Hardening/passwd
cp -rfp /etc/shadow /root/Desktop/BackupB4Hardening/shadow
cp -rfp /etc/inittab /root/Desktop/BackupB4Hardening/inittab

echo -e "#######################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e " FILE PERMISSION IN BACKUP DIRECTORY" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "#######################################" >> /root/Desktop/BackupB4Hardening/output.txt

/bin/ls -l /root/Desktop/BackupB4Hardening/su >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/resolv.conf >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/client.repo >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/ntp.conf >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/limits.conf >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/rsyslog.conf >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/at.deny >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/cron.deny >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/login.defs >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/.bash_profile >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/bashrc >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/functions >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/ssh_config >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/sshd_config >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/inittab >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/issue.net >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/issue >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/motd >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/passwd >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/sysctl.conf >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/system-auth-ac >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/grub.conf >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/securetty >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/fstab >> /root/Desktop/BackupB4Hardening/output.txt

/bin/echo "######################################################"
/bin/echo "Files have been copied to /root/Desktop/BackupB4Hardening directory "
/bin/echo "######################################################"


echo "############ Lock the Unneccessary Accounts ##############" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############ Lock the Unneccessary Accounts ##############"
for i in rpc rpcuser lp named dns mysql postgres squid news netdump
do
usermod -L -s /sbin/nologin $i &>/dev/null
echo -e "Unnecessary user $i has been locked ... !!!"
done
sleep 1

echo -e "Folowing Unnecessary users have been locked \n rpc\n rpcuser\n lp\n named\n dns\n mysql\n postgres\n squid\n news\n netdump" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################"
sleep 3

echo -e "######## Block System Accounts #######"
echo -e "#####################################"
echo -e "######## Block System Accounts #######" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "#####################################" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 2
for NAME in `cut -d: -f1 /etc/passwd`;
do
MyUID=`id -u $NAME`
if [ $MyUID -lt 500 -a $NAME != 'root' ]; then
usermod -L -s /sbin/nologin $NAME
echo -e "System Account $NAME has been blocked"
echo -e "System Account $NAME has been blocked" >> /root/Desktop/BackupB4Hardening/output.txt
fi
done
echo -e "#####################################"
echo -e "#####################################" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 3

echo -e "###### Verify passwd, shadow and group file permissions #######"
echo -e "###### Verify passwd, shadow and group file permissions #######" >> /root/Desktop/BackupB4Hardening/output.txt

echo -e "Set permission of /etc/passwd 0444"
echo -e "Set permission of /etc/passwd 0444" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "chmod 0444 /etc/passwd" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "chmod 0444 /etc/passwd"
chmod 0444 /etc/passwd
echo -e "ls -l /etc/passwd /etc/group /etc/shadow"
echo -e "ls -l /etc/passwd /etc/group /etc/shadow" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 2
ls -l /etc/passwd /etc/group /etc/shadow
ls -l /etc/passwd /etc/group /etc/shadow >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "#####################################"
echo -e "#####################################" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 2

echo -e  "##### Verify that no UID 0 Account exists Other than root #####"
echo -e "###### Verify that no UID 0 Account exists Other than root #####" >> /root/Desktop/BackupB4Hardening/output.txt
awk -F: '($3 == 0) { print "UID 0 Accounts are Below. Please do block if its not neccessary\n" $1 }' /etc/passwd
sleep 3
awk -F: '($3 == 0) { print "UID 0 Accounts are Below. Please do block if its not neccessary\n" $1 }' /etc/passwd >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "#####################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "#####################################"
sleep 2


######Banner#####
echo "Updating the banner in /root/banner file" >> /root/Desktop/BackupB4Hardening/output.txt
cat > /root/banner << EOF
##################################################################
|This system is for the use of authorized users only.            |
|Individuals using this computer system without authority, or in |
|excess of their authority, are subject to having all of their   |
|activities on this system monitored and recorded by system      |
|personnel.                                                      |
|In the course of monitoring individuals improperly using this   |
|system, or in the course of system maintenance, the activities  |
|of authorized users may also be monitored.                      |
|Anyone using this system expressly consents to such monitoring  |
|and is advised that if such monitoring reveals possible         |
|evidence of criminal activity, system personnel may provide the |
|evidence of such monitoring to law enforcement officials.       |
##################################################################
EOF
cat /root/banner >> /root/Desktop/BackupB4Hardening/output.txt
cat /root/banner
sleep 2
#cp -rfp /etc/issue.net /root/Desktop/BackupB4Hardening/issue.net
#cp -rfp /etc/motd /root/Desktop/BackupB4Hardening/motd
#cp -rfp /etc/issue /root/Desktop/BackupB4Hardening/issue

cat /root/banner > /etc/issue.net
echo "Banner for /etc/issue.net"
cat /etc/issue.net
echo "Banner for /etc/issue"
cat /root/banner > /etc/issue
cat /etc/issue
echo "Banner for /etc/motd"
cat /root/banner > /etc/motd
cat /etc/motd
rm -rf /root/banner
echo -e "#####################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "#####################################"
sleep 2

echo -e "############### Default RRunlevel ###########################"
echo -e "############### Default RRunlevel ###########################" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "Change the default Run level to 3"
echo -e "Change the default Run level to 3" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 3
#cp -rfp /etc/inittab /root/Desktop/BackupB4Hardening/inittab
echo -e "cp -rfp /etc/inittab /root/Desktop/BackupB4Hardening/inittab" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "sed -i 's/id:5:initdefault:/id:3:initdefault:/g' /etc/inittab"
echo -e "sed -i 's/ca::ctrlaltdel:/#ca::ctrlaltdel:/g' /etc/inittab"
echo -e "sed -i 's/id:5:initdefault:/id:3:initdefault:/g' /etc/inittab" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "sed -i 's/ca::ctrlaltdel:/#ca::ctrlaltdel:/g' /etc/inittab" >> /root/Desktop/BackupB4Hardening/output.txt
sed -i 's/id:5:initdefault:/id:3:initdefault:/g' /etc/inittab
sed -i 's/ca::ctrlaltdel:/#ca::ctrlaltdel:/g' /etc/inittab

echo -e "Runlevel has been changed to `grep id /etc/inittab | awk -F':' '{print$2}'`"
echo -e "Runlevel has been changed to `grep id /etc/inittab | awk -F':' '{print$2}'`" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 3
echo -e "#####################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "#####################################"
sleep 2

echo -e "############ ssh configuration ############"
echo -e "############ ssh configuration ############" >> /root/Desktop/BackupB4Hardening/output.txt
echo "Configuring SSH service"
echo "Configuring SSH service" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 3


#cp -rfp /etc/ssh/ssh_config /root/Desktop/BackupB4Hardening/ssh_config
#cp -rfp /etc/ssh/sshd_config /root/Desktop/BackupB4Hardening/sshd_config

service sshd restart
service sshd restart  >> /root/Desktop/BackupB4Hardening/output.txt 2>/dev/null

#sed -e 's/#PermitRootLogin yes/PermitRootLogin no/g' sshd_config >>sshd_config1
#cp -p sshd_config sshd_config.before
#mv sshd_config1 sshd_config
#echo Banner /root/banner >> /etc/ssh/sshd_config
echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################"
sleep 2

echo -e "##### Setting Password Expiry Time for users ...#####"
echo -e "##### Setting Password Expiry Time for users ...#####" >> /root/Desktop/BackupB4Hardening/output.txt
#cp -rfp /etc/login.defs /root/Desktop/BackupB4Hardening/login.defs
sleep 2
/bin/sed -i 's/99999/45/g' /etc/login.defs
echo -e "Maximum number of days a password may be used is set to 45" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "Maximum number of days a password may be used is set to 45"

#/bin/sed -i 's/PASS_MIN_LEN\s5/PASS_MIN_LEN\t8/g' /etc/login.defs
sed -i 's/^PASS_MIN_LEN/#PASS_MIN_LEN/g' /etc/login.defs
echo -e "PASS_MIN_LEN\t8" >> /etc/login.defs
echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################################"
sleep 2

echo -e "############## Set Daemon Umask ################"
echo -e "############## Set Daemon Umask ################" >> /root/Desktop/BackupB4Hardening/output.txt
#cp -rfp /etc/init.d/functions /root/Desktop/BackupB4Hardening/functions

# edit the line with umask
#sed -e 's/umask 022/umask 027/g' functions >>functions1
#cp -p functions functions.before
#mv functions1 functions
#echo "All the activities are done by this script has been logged into $HARD_LOG"

#cp -rfp /etc/bashrc /root/Desktop/BackupB4Hardening/bashrc

echo -e "Set umask as 022"
echo -e "Set umask as 022" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 2
#echo "umask 022" >> /etc/bashrc
sed -e "s/umask 002/umask 022/g" /etc/bashrc > test ; cat test > /etc/bashrc
source /etc/bashrc

# edit the line with umask
#sed -e 's/umask 002/umask 022/g' bashrc >>bashrc1
#cp -p bashrc bashrc.before
#mv bashrc1 bashrc
echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################################"
sleep 2

echo -e "############## Set Profile Umask ###############"
echo -e "############## Set Profile Umask ###############" >> /root/Desktop/BackupB4Hardening/output.txt
#cp -rfp /root/.bash_profile /root/Desktop/BackupB4Hardening/bash_profile

echo -e "Set Profile Umask as 022"
echo -e "Set Profile Umask as 022" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 2
echo "umask 022" >> /root/.bash_profile
source /root/.bash_profile

echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################################"
sleep 2

echo -e "####### Confirm Permissions On System Log files ########"
echo -e "####### Confirm Permissions On System Log files ########" >> /root/Desktop/BackupB4Hardening/output.txt
/bin/chmod 751 /var/log
ls -l  /var/log
ls -l  /var/log >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "#####################################"
echo -e "#####################################" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 2


echo -e "### Restrict Root Logins To System Console By adding the entry called console in the file /etc/securetty #####
echo "Restricting root Logins to the System Console By adding the entry called console in the file /etc/securetty" >> /root/Desktop/BackupB4Hardening/output.txt
#for i in 'seq 1 6'; do
#echo tty$i >> /etc/securetty
#done
#for i in 'seq 1 11'; do
#echo vc/$i >> /etc/securetty
#done
#echo console >> /etc/securetty
echo -e "chown root:root /etc/securetty"
echo -e "chown root:root /etc/securetty" >> /root/Desktop/BackupB4Hardening/output.txt
chown root:root /etc/securetty
sleep 2
echo -e "chmod 0600 /etc/securetty"
echo -e "chmod 0600 /etc/securetty" >> /root/Desktop/BackupB4Hardening/output.txt
chmod 0600 /etc/securetty
sleep 2
echo -e "Set Protocol 2 for ssh"
echo -e "Set Protocol 2 for ssh" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "Protocol 2" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "Protocol 2" >> /etc/ssh/sshd_config
sleep 2
echo -e "Set ENCRYPT METHOD"
echo -e "Set ENCRYPT METHOD" >> /root/Desktop/BackupB4Hardening/output.txt
echo "ENCRYPT_METHOD SHA512 " >> /root/Desktop/BackupB4Hardening/output.txt
echo "ENCRYPT_METHOD SHA512 " >> /etc/login.defs
sleep 2
echo -e "Set Password Minimum Length"
echo -e "Set Password Minimum Length" >> /root/Desktop/BackupB4Hardening/output.txt
echo "PASS_MIN_LEN      8" >> /root/Desktop/BackupB4Hardening/output.txt
echo "PASS_MIN_LEN      8" >> /etc/login.defs
sleep 2
echo -e "chmod 0644 /var/log/lastlog"
echo -e "chmod 0644 /var/log/lastlog" >> /root/Desktop/BackupB4Hardening/output.txt
chmod 0644 /var/log/lastlog
echo -e "#####################################"
echo -e "#####################################" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 2
#cp -rfp /etc/pam.d/su  /root/Desktop/BackupB4Hardening/su 
/bin/sed -r 's/^#(.*required\s+pam_wheel\.so use_uid.*)/\1/' /etc/pam.d/su > /etc/pam.d/su1
rm -rf /etc/pam.d/su
mv /etc/pam.d/su1 /etc/pam.d/su

#echo -e "auth required pam_wheel.so use_uid Add This to /etc/pam.d/su" >> /root/Desktop/BackupB4Hardening/output.txt
#echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################"
sleep 3

echo "###########################################################################################
###########################Services Should be on ##########################################"
echo "###########################################################################################
###########################Services Should be on ##########################################">> /root/Desktop/BackupB4Hardening/output.txt
sleep 2

echo "chkconfig --level 0123456 acpid on
chkconfig --level 0123456 anacron on
chkconfig --level 0123456 lvm2-monitor on
chkconfig --level 0123456  messagebus on
chkconfig --level 0123456  network on
chkconfig --level 0123456  readahead_early on
chkconfig --level 0123456 readahead_later on
chkconfig --level 0123456 syslog on
chkconfig --level 0123456 rsyslog on
chkconfig --level 0123456 sshd on
chkconfig --level 0123456 auditd on
chkconfig --level 0123456 crond on
chkconfig --level 0123456 ntpd on
chkconfig --level 0123456 ntpdate on
chkconfig --level 0123456 sysstat on" 
sleep 4
echo "chkconfig --level 0123456 acpid on
chkconfig --level 0123456 anacron on
chkconfig --level 0123456 lvm2-monitor on
chkconfig --level 0123456  messagebus on
chkconfig --level 0123456  network on
chkconfig --level 0123456  readahead_early on
chkconfig --level 0123456 readahead_later on
chkconfig --level 0123456 syslog on
chkconfig --level 0123456 rsyslog on
chkconfig --level 0123456 sshd on
chkconfig --level 0123456 auditd on
chkconfig --level 0123456 crond on
chkconfig --level 0123456 ntpd on
chkconfig --level 0123456 ntpdate on
chkconfig --level 0123456 sysstat on" >> /root/Desktop/BackupB4Hardening/output.txt

/sbin/chkconfig --level 0123456 acpid on
/sbin/chkconfig --level 0123456 anacron on
/sbin/chkconfig --level 0123456 lvm2-monitor on
/sbin/chkconfig --level 0123456  messagebus on
/sbin/chkconfig --level 0123456  network on
/sbin/chkconfig --level 0123456  readahead_early on
/sbin/chkconfig --level 0123456 readahead_later on
/sbin/chkconfig --level 0123456 syslog on
/sbin/chkconfig --level 0123456 rsyslog on
/sbin/chkconfig --level 0123456 sshd on
/sbin/chkconfig --level 0123456 auditd on
/sbin/chkconfig --level 0123456 crond on
/sbin/chkconfig --level 0123456 ntpd on
/sbin/chkconfig --level 0123456 ntpdate on
/sbin/chkconfig --level 0123456 sysstat on

echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################"
sleep 3

echo "###################Services Should be stop/save/restart####################################" 
echo "###################Services Should be stop/save/restart####################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "Stop The xinetd Service
restart ntpd Service
restart auditd Service" >> /root/Desktop/BackupB4Hardening/output.txt
#/etc/init.d/sshd restart
#/etc/init.d/ntpdate stop
sleep 2
echo "/etc/init.d/xinetd stop
/etc/init.d/ntpd restart
/etc/init.d/auditd restart" >> /root/Desktop/BackupB4Hardening/output.txt
#/etc/init.d/sshd restart
#/etc/init.d/ntpdate stop 

/etc/init.d/xinetd stop
/etc/init.d/ntpd restart
/etc/init.d/auditd restart
#/etc/init.d/sshd restart
#/etc/init.d/ntpdate stop

sleep 3
echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################"
sleep 3

echo -e"################ The following services should be off ####################################"
echo -e"################ The following services should be off ####################################" >> /root/Desktop/BackupB4Hardening/output.txt

echo -e "chkconfig --level 0123456 xinetd off 
chkconfig --level 0123456 atd off 
chkconfig --level 0123456 nfs off
chkconfig --level 0123456 tcpmux-server off
chkconfig --level 0123456 cups off
chkconfig --level 0123456 nfslock off 
#chkconfig --level 0123456  rpcbind off 
chkconfig --level 0123456 rpcidmapd off 
chkconfig --level 0123456 rpcsvcgssd off
chkconfig --level 0123456 autofs off 
chkconfig --level 0123456 cpuspeed off 
chkconfig --level 0123456  acpid off 
chkconfig --level 0123456 sendmail off
#chkconfig --level 0123456 abrtd off
#chkconfig --level 0123456 ntpdate off"
#######/sbin/chkconfig --level 0123456 haldaemon off 
#######/sbin/chkconfig --level 0123456  messagebus off 
#/sbin/chkconfig --level 0123456 ntpdate off
#/sbin/chkconfig --level 0123456  sysstat off 
#configure hosts.deny and hosts.allow 
echo -e "chkconfig --level 0123456 xinetd off
chkconfig --level 0123456 atd off
chkconfig --level 0123456 nfs off
chkconfig --level 0123456 tcpmux-server off
chkconfig --level 0123456 cups off
chkconfig --level 0123456 nfslock off
chkconfig --level 0123456  rpcbind off
chkconfig --level 0123456 rpcidmapd off
chkconfig --level 0123456 rpcsvcgssd off
chkconfig --level 0123456 autofs off
chkconfig --level 0123456 cpuspeed off
chkconfig --level 0123456  acpid off
chkconfig --level 0123456 abrtd off
chkconfig --level 0123456 sendmail off
chkconfig --level 0123456 ntpdate off" >> /root/Desktop/BackupB4Hardening/output.txt

/sbin/chkconfig --level 0123456 xinetd off 
/sbin/chkconfig --level 0123456 atd off 
/sbin/chkconfig --level 0123456 nfs off
/sbin/chkconfig --level 0123456 tcpmux-server off
/sbin/chkconfig --level 0123456 cups off
/sbin/chkconfig --level 0123456 nfslock off 
/sbin/chkconfig --level 0123456  rpcbind off 
/sbin/chkconfig --level 0123456 rpcidmapd off 
/sbin/chkconfig --level 0123456 rpcsvcgssd off
/sbin/chkconfig --level 0123456 autofs off 
/sbin/chkconfig --level 0123456 cpuspeed off 
#######/sbin/chkconfig --level 0123456 haldaemon off 
#######/sbin/chkconfig --level 0123456  messagebus off 
/sbin/chkconfig --level 0123456  acpid off 
/sbin/chkconfig cron off --level 0123456
/sbin/chkconfig --level 0123456 abrtd off
/sbin/chkconfig --level 0123456 ntpdate off
/sbin/chkconfig --level 0123456 sendmail off
#/sbin/chkconfig --level 0123456  sysstat off 
#configure hosts.deny and hosts.allow 


echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################"
sleep 3
######################Following Packages should be removed#################################"
######################Following Packages should be removed#################################

#yum remove -y setroubleshoot
#yum remove -y mcstrans
#yum remove -y telnet-server
#yum remove -y telnet
#yum remove -y rsh-server
#yum remove -y rsh
#yum remove -y ypbind
#yum remove -y ypserver
#yum remove -y tftp
#yum remove -y tftp-server
#yum remove -y talk
#yum remove -y  dhcp
#yum remove -y  openldap-servers 
#yum remove -y  openldap-clients
#yum remove -y  bind
#yum remove -y  vfstpd
#yum remove -y  dovecot
#yum remove -y  samba
#yum remove -y  squid
#yum remove -y  netsnmp
#yum remove -y  xorg-x11-server-common
#yum remove -y setroubleshoot
#yum remove -y mcstrans

#echo "umask 027"  /etc/sysconfig/init
echo -e "########################### Modify owner and group ###############"
echo -e "########################### Modify owner and group ###############" >> /root/Desktop/BackupB4Hardening/output.txt

echo -e "chown root:root /boot/grub/grub.conf
chown root:root /etc/cron.d
chown root:root /etc/cron.hourly
chown root:root /etc/cron.daily 
chown root:root /etc/cron.weekly 
chown root:root /etc/cron.monthly 
chown root:root /etc/cron.allow
chown root:root /etc/ssh/sshd_config
chown root:root /etc/rsyslog.conf
chown root:root /etc/motd
chown root:root /etc/issue
chown root:root /etc/issue.net
chown root:root /etc/passwd
chown root:root /etc/shadow
chown root:root /etc/gshadow
chown root:root /etc/group
chown root:root /var/log/btmp
chown root:root /var/log/wtmp
chown root:root /var/log/lastlog
chown root:root /var/log/messages
chown root:root /var/log/sa
chown root:root /var/log/samba
chown root:root /etc/cron.allow"
sleep 3
echo "chown root:root /boot/grub/grub.conf
chown root:root /etc/cron.d
chown root:root /etc/cron.hourly
chown root:root /etc/cron.daily 
chown root:root /etc/cron.weekly 
chown root:root /etc/cron.monthly 
chown root:root /etc/cron.allow
chown root:root /etc/ssh/sshd_config
chown root:root /etc/rsyslog.conf
chown root:root /etc/motd
chown root:root /etc/issue
chown root:root /etc/issue.net
chown root:root /etc/passwd
chown root:root /etc/shadow
chown root:root /etc/gshadow
chown root:root /etc/group
chown root:root /var/log/btmp
chown root:root /var/log/wtmp
chown root:root /var/log/lastlog
chown root:root /var/log/messages
chown root:root /var/log/sa
chown root:root /var/log/samba
chown root:root /etc/cron.allow" >> /root/Desktop/BackupB4Hardening/output.txt

chown root:root /boot/grub/grub.conf
chown root:root /etc/cron.d
chown root:root /etc/cron.hourly
chown root:root /etc/cron.daily 
chown root:root /etc/cron.weekly 
chown root:root /etc/cron.monthly 
chown root:root /etc/cron.allow
chown root:root /etc/ssh/sshd_config
chown root:root /etc/rsyslog.conf
chown root:root /etc/motd
chown root:root /etc/issue
chown root:root /etc/issue.net
chown root:root /etc/passwd
chown root:root /etc/shadow
chown root:root /etc/gshadow
chown root:root /etc/group
chown root:root /var/log/btmp
chown root:root /var/log/wtmp
chown root:root /var/log/lastlog
chown root:root /var/log/messages
chown root:root /var/log/sa
chown root:root /var/log/samba
chown root:root /etc/cron.allow

echo -e "############### Change The Permission Of Follwing Files ############"
echo -e "############### Change The Permission Of Follwing Files ############" >> /root/Desktop/BackupB4Hardening/output.txt

echo "chmod 0600 /etc/cron.d
chmod 0751 /var/log
chmod og-rwx /etc/cron.hourly
chmod og-rwx /etc/cron.daily
chmod og-rwx /etc/cron.weekly
chmod og-rwx /etc/cron.monthly
chmod og-rwx /etc/cron.allow
chmod 0600 /etc/ssh/sshd_config
chmod 0644 /etc/motd
chmod 0644 /etc/issue
chmod 0644 /etc/issue.net
chmod 0400 /etc/shadow
chmod 0644 /etc/group
chmod 0444 /etc/passwd
chmod 0400 /etc/gshadow
chmod 0644 /var/log/btmp
chmod 0600 /var/log/wtmp
chmod 0622 /var/log/lastlog
chmod 0600 /var/log/messages
chmod 0644 /var/log/sa
chmod 0644 /var/log/samba
chmod 0750 /etc/abrt
chmod 0750 /var/lib/nfs
chmod 0750 /var/lib/qpidd
chmod 0644 /etc/crontab
chmod 0644 /etc/inittab
chmod 700 /etc/rsyslog.conf
chmod 0644 /etc/sysctl.conf
chmod 750 /etc/pam.d
chmod 751 /etc/sysconfig
chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny
chmod 0644 /var/spool/cron
chmod 0600 /etc/securetty"


echo -e "chmod 0600 /etc/cron.d
chmod 0751 /var/log
chmod og-rwx /etc/cron.hourly
chmod og-rwx /etc/cron.daily
chmod og-rwx /etc/cron.weekly
chmod og-rwx /etc/cron.monthly
chmod og-rwx /etc/cron.allow
chmod 0600 /etc/ssh/sshd_config
chmod 0644 /etc/motd
chmod 0644 /etc/issue
chmod 0644 /etc/issue.net
chmod 0400 /etc/shadow
chmod 0644 /etc/group
chmod 0444 /etc/passwd
chmod 0400 /etc/gshadow
chmod 0644 /var/log/btmp
chmod 0600 /var/log/wtmp
chmod 0622 /var/log/lastlog
chmod 0600 /var/log/messages
chmod 0644 /var/log/sa
chmod 0644 /var/log/samba
chmod 0750 /etc/abrt
chmod 0750 /var/lib/nfs
chmod 0750 /var/lib/qpidd
chmod 0644 /etc/crontab
chmod 0644 /etc/inittab
chmod 700 /etc/rsyslog.conf
chmod 0644 /etc/sysctl.conf
chmod 750 /etc/pam.d
chmod 751 /etc/sysconfig
chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny
chmod 0644 /var/spool/cron
chmod 0600 /etc/securetty" >> /root/Desktop/BackupB4Hardening/output.txt

chmod 0600 /etc/cron.d
chmod 0751 /var/log
chmod og-rwx /etc/cron.hourly
chmod og-rwx /etc/cron.daily
chmod og-rwx /etc/cron.weekly
chmod og-rwx /etc/cron.monthly
chmod og-rwx /etc/cron.allow
chmod 0600 /etc/ssh/sshd_config
chmod 0644 /etc/motd
chmod 0644 /etc/issue
chmod 0644 /etc/issue.net
chmod 0400 /etc/shadow
chmod 0644 /etc/group
chmod 0444 /etc/passwd
chmod 0400 /etc/gshadow
chmod 0644 /var/log/btmp
chmod 0600 /var/log/wtmp
chmod 0622 /var/log/lastlog
chmod 0600 /var/log/messages
chmod 0644 /var/log/sa
chmod 0644 /var/log/samba
chmod 0750 /etc/abrt
chmod 0750 /var/lib/nfs
chmod 0750 /var/lib/qpidd
chmod 0644 /etc/crontab
chmod 0644 /etc/inittab
chmod 700 /etc/rsyslog.conf
chmod 0644 /etc/sysctl.conf
chmod 750 /etc/pam.d
chmod 751 /etc/sysconfig
chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny
chmod 0644 /var/spool/cron
chmod 0600 /etc/securetty

echo -e "##################### Configure /etc/at.allow #################"
echo -e "##################### Configure /etc/at.allow #################" >>  /root/Desktop/BackupB4Hardening/output.txt
#cp -rpf /etc/cron.allow /root/Desktop/BackupB4Hardening/cron.allow
#echo -e "cp -rpf /etc/cron.allow /root/Desktop/BackupB4Hardening/cron.allow" >> /root/Desktop/BackupB4Hardening/output.txt
#cp -rpf /etc/at.allow /root/Desktop/BackupB4Hardening/at.allow
#echo -e "cp -rpf /etc/at.allow /root/Desktop/BackupB4Hardening/at.allow" >> /root/Desktop/BackupB4Hardening/output.txt
#/bin/ls -l /etc/hosts.deny /etc/hosts.allow /etc/securetty /var/spool/cron  >>  /root/Desktop/BackupB4Hardening/output.txt
#echo -e "This files is created  /etc/cron.allow /etc/at.allow" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 2
#/bin/touch /etc/cron.allow
#/bin/touch /etc/at.allow
#/bin/ls -l /etc/at.allow /etc/cron.allow >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "Adding ROOT Entry into the /etc/cron.allow & /etc/at.allow" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "Adding ROOT Entry into the /etc/cron.allow & /etc/at.allow"
sleep 2
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow

chmod 0400 /etc/cron.allow
/bin/ls -l /etc/cron.allow >> /root/Desktop/BackupB4Hardening/output.txt

echo -e "############# Change Owner and Group of /etc/at.allow to root #############"
echo -e "############# Change Owner and Group of /etc/at.allow to root #############" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "chown root:root /etc/at.allow" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "chown root:root /etc/at.allow"
chown root:root /etc/at.allow 
echo -e "chmod 0400 /etc/at.allow"
echo -e "chmod 0400 /etc/at.allow" >> /root/Desktop/BackupB4Hardening/output.txt
chmod 0400 /etc/at.allow
/bin/ls -l  /etc/at.allow
/bin/ls -l  /etc/at.allow >> /root/Desktop/BackupB4Hardening/output.txt
sleep 2
#cp -rfp /etc/cron.deny /root/Desktop/BackupB4Hardening/cron.deny 
#cp -rfp /etc/at.deny /root/Desktop/BackupB4Hardening/at.deny  

/bin/ls -l /root/Desktop/BackupB4Hardening/cron.deny >> /root/Desktop/BackupB4Hardening/output.txt
/bin/ls -l /root/Desktop/BackupB4Hardening/at.deny >> /root/Desktop/BackupB4Hardening/output.txt

echo -e "Removing /etc/cron.deny & /etc/at.deny Files " >> /root/Desktop/BackupB4Hardening/output.txt
sleep 1
/bin/rm -f /etc/cron.deny
/bin/rm -f /etc/at.deny
sleep 1

echo -e "############# 50-default.perms ###################"
echo -e "############# 50-default.perms ###################" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "Creating File /etc/security/console.perms.d/50-default.perms" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "Creating File /etc/security/console.perms.d/50-default.perms"
sleep 3
touch /etc/security/console.perms.d/50-default.perms
/bin/ls -l  /etc/security/console.perms.d/50-default.perms >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "chmod 0600 /etc/security/console.perms.d/50-default.perms"
chmod 0600 /etc/security/console.perms.d/50-default.perms
/bin/ls -l /etc/security/console.perms.d/50-default.perms >> /root/Desktop/BackupB4Hardening/output.txt
sleep 3


echo -e "############# 50-default.perms ###################" 
echo -e "############# 50-default.perms ###################" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "########### Creating File /etc/security/console.perms.d/50-default ###########" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 1
echo -e "touch /etc/security/console.perms.d/50-default" >> /root/Desktop/BackupB4Hardening/output.txt
echo -e "touch /etc/security/console.perms.d/50-default"
touch /etc/security/console.perms.d/50-default
/bin/ls -l /etc/security/console.perms.d/50-default >> /root/Desktop/BackupB4Hardening/output.txt 
/bin/ls -l /etc/security/console.perms.d/50-default
echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################"
sleep 3

chmod -s /bin/ping6 /bin/cgexec /bin/mount /bin/ping /bin/umount /sbin/netreport /sbin/unix_chkpwd /sbin/mount.nfs /sbin/pam_timestamp_check
chmod -s /usr/sbin/usernetctl /usr/sbin/postdrop /usr/sbin/postqueue /usr/sbin/userhelper /usr/libexec/polkit-1/polkit-agent-helper-1 /usr/libexec/abrt-action-install-debuginfo-to-abrt-cache /usr/libexec/pt_chown /usr/libexec/utempter/utempter /usr/libexec/openssh/ssh-keysign /usr/bin/pkexec /usr/bin/sudoedit /usr/bin/staprun /usr/bin/passwd /usr/bin/write /usr/bin/newgrp /usr/bin/ssh-agent /usr/bin/sudo /usr/bin/chfn /usr/bin/at /usr/bin/gpasswd /usr/bin/chage /usr/bin/ksu /usr/bin/wall /usr/bin/locate /usr/bin/chsh /usr/bin/crontab
chmod -s /lib64/dbus-1/dbus-daemon-launch-helper

echo -e "############# rsyslog.conf ###################"
echo -e "############# rsyslog.conf ###################" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 2
#cp -rfp /etc/rsyslog.conf /root/Desktop/BackupB4Hardening/rsyslog.conf
/bin/ls -l /root/Desktop/BackupB4Hardening/rsyslog.conf >> /root/Desktop/BackupB4Hardening/output.txt


echo "# The authpriv file has restricted access." >> /etc/rsyslog.conf
echo "auth.*,user.*             /var/log/messages" >> /etc/rsyslog.conf

echo -e "chmod 0644 /etc/at.allow"
chmod 0644 /etc/at.allow
/bin/ls -l /etc/at.allow >> /root/Desktop/BackupB4Hardening/output.txt

echo -e "Copy /etc/audit/auditd.conf To /etc/audit/audit.conf" >> /root/Desktop/BackupB4Hardening/output.txt
cp -rfp /etc/audit/auditd.conf /etc/audit/audit.conf
cp -rfp /etc/audit/audit.conf /root/Desktop/BackupB4Hardening/audit.conf
/bin/ls -l /etc/audit/audit.conf >> /root/Desktop/BackupB4Hardening/output.txt

#echo -e "This opration is not performed if you want then uncomment the lines
#chmod 0400 /etc/gshadow
#chmod 0400 /etc/shadow
#chmod 0400 /etc/at.allow
#chmod 0400 /etc/inittab	
#chmod 0600 /root/Desktop/BackupB4Hardening/log/messages /root/Desktop/BackupB4Hardening/log/lastlog
#Copy password of /etc/grub.cong
#sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config
#sed -i "/SINGLE/s/sushell/sulogin/" /etc/sysconfig/init"
#chmod 0400 /etc/gshadow
#chmod 0400 /etc/shadow
#chmod 0400 /etc/at.allow
#chmod 0400 /etc/inittab
#chmod 0600 /root/Desktop/BackupB4Hardening/log/messages /root/Desktop/BackupB4Hardening/log/lastlog
#Copy password of /etc/grub.cong
#sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config
#sed -i "/SINGLE/s/sushell/sulogin/" /etc/sysconfig/init"


#echo -e "Installing aide-0.14-3.el6.x86_64.rpm" >> /root/Desktop/BackupB4Hardening/output.txt
#sleep 1
#rpm -ivh aide-0.14-3.el6.x86_64.rpm

#configure hosts.deny and hosts.allow 
#configure nousb in /boot/grub/grub.conf

echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################"
sleep 3
echo -e "Setting crontab entries"
echo -e "Setting crontab entries" >> /root/Desktop/BackupB4Hardening/output.txt
echo "0 5 * * * /usr/sbin/aide --check" >> root
crontab root
crontab -l -u root
crontab -l -u root >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################"
sleep 3
echo -e "root" > /etc/cron.allow
echo -e "0 5 * * * /usr/sbin/aide --check" > /var/spool/cron/root

#############configure ntp.conf############################33

#sed -i 's/server 0.rhel.pool.ntp.org iburst/server 10.204.0.2 true /' /etc/ntp.conf
#sed -i 's/server 0.rhel.pool.ntp.org iburst/server 10.204.0.3  /' /etc/ntp.conf
#echo -e "Configuring ntp.conf"
#echo -e "Add NTP servers IPs" >> /root/Desktop/BackupB4Hardening/output.txt
#sleep 1
#echo "server 10.204.0.2 true " >> /etc/ntp.conf
#echo "server 10.204.0.3 " >> /etc/ntp.conf

#echo -e "Chkconfig NTP on Level 3 & 5" >> /root/Desktop/BackupB4Hardening/output.txt
#sleep 1
#/sbin/chkconfig --level 35 ntpd on
#echo "Restarting NTP service" >> /root/Desktop/BackupB4Hardening/output.txt
#sleep 1
#/etc/init.d/ntpd restart
#/usr/sbin/ntpq -p 
#sleep 5
#/usr/sbin/ntpq -p >> /root/Desktop/BackupB4Hardening/output.txt
#rcntp ntptimeset


####################################################################
#sed -i 's/server 0.rhel.pool.ntp.org iburst/server dc1ntp.idc.ril.com /' /etc/ntp.conf
#sed -i 's/server 1.rhel.pool.ntp.org iburst/server idc1ntp1.idc.ril.com /' /etc/ntp.conf
#sed -i 's/server 2.rhel.pool.ntp.org iburst/#server 2.rhel.pool.ntp.org iburst/' /etc/ntp.conf
#sed -i 's/server 3.rhel.pool.ntp.org iburst/#server 3.rhel.pool.ntp.org iburst/' /etc/ntp.conf
#/usr/sbin/ntpq -p

echo "##########################ADDITIONAL LINES#######################################" >>/etc/sysctl.conf
echo "##########################ADDITIONAL LINES IN /etc/sysctl.conf #######################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "net.ipv4.conf.all.rp_filter = 1
kernel.exec-shield = 1
kernel.randomize_va_space = 2
fs.inotify.max_user_watches = 65536
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_igNore_bogus_error_messages= 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_echo_igNore_broadcasts=1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.ip_forward = 0
net.ipv4.ip_local_port_range = 40000 65300
net.ipv4.conf.default.promote_secondaries = 1
net.ipv4.conf.all.promote_secondaries = 1
net.core.rmem_default = 64000000" >> /root/Desktop/BackupB4Hardening/output.txt

echo "net.ipv4.conf.all.rp_filter = 1
kernel.exec-shield = 1
kernel.randomize_va_space = 2
fs.inotify.max_user_watches = 65536
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_igNore_bogus_error_messages= 1
#echo #net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_echo_igNore_broadcasts=1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.ip_forward = 0
net.ipv4.ip_local_port_range = 40000 65300
net.ipv4.conf.default.promote_secondaries = 1
net.ipv4.conf.all.promote_secondaries = 1
net.core.rmem_default = 64000000" 

echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
echo "fs.inotify.max_user_watches = 65536"  >> /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
echo "net.ipv4.icmp_igNore_bogus_error_messages= 1" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_max_syn_backlog = 4096" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 4096" >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
echo  "net.ipv4.icmp_echo_igNore_broadcasts=1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf 
echo "net.ipv4.ip_local_port_range = 40000 65300" >> /etc/sysctl.conf 
echo "net.ipv4.conf.default.promote_secondaries = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.promote_secondaries = 1" >> /etc/sysctl.conf
echo  "net.core.rmem_default = 64000000" >> /etc/sysctl.conf
sleep 3
####################################################################
echo -e "############ TCP optimization Add This entries in to /etc/sysctl.conf ############"
echo -e "############ TCP optimization Add This entries in to /etc/sysctl.conf ############" >> /root/Desktop/BackupB4Hardening/output.txt
echo "# TCP optimization Add This entries in to /etc/sysctl.conf" >> /root/Desktop/BackupB4Hardening/output.txt
echo "net.core.rmem_default = 64000000
net.core.rmem_max = 64000000
net.core.wmem_default = 32000000
net.core.wmem_max = 32000000
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 0"
sleep 2
echo "# TCP optimization
net.core.rmem_default = 64000000
net.core.rmem_max = 64000000 
net.core.wmem_default = 32000000 
net.core.wmem_max = 32000000 
net.ipv4.tcp_timestamps = 0 
net.ipv4.tcp_sack = 0" >>  /root/Desktop/BackupB4Hardening/output.txt
sleep 1
echo "# TCP optimization" >> /etc/sysctl.conf
echo "net.core.rmem_default = 64000000" >> /etc/sysctl.conf
echo "net.core.rmem_max = 64000000" >>  /etc/sysctl.conf
echo "net.core.wmem_default = 32000000" >> /etc/sysctl.conf
echo "net.core.wmem_max = 32000000" >>  /etc/sysctl.conf
echo "net.ipv4.tcp_timestamps = 0" >>  /etc/sysctl.conf
echo "net.ipv4.tcp_sack = 0" >>  /etc/sysctl.conf
sleep 2
echo -e "#Parameters recommended for Mellanox/RDMA cards
net.ipv4.tcp_max_orphans = 562144
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_mem = 100000000    100000000       100000000"

echo "#Parameters recommended for Mellanox/RDMA cards
net.ipv4.tcp_max_orphans = 562144
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_mem = 100000000    100000000       100000000" >>  /root/Desktop/BackupB4Hardening/output.txt

sleep 2

echo "#Parameters recommended for Mellanox/RDMA cards" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_orphans = 562144" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_tw_buckets = 1440000" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_max_syn_backlog = 2048" >> /etc/sysctl.conf
echo "net.ipv4.tcp_mem = 100000000    100000000       100000000" >>  /etc/sysctl.conf


echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################"
sleep 3

echo -e "Adding Entries in /etc/sysctl.conf"
echo -e "Adding Entries in /etc/sysctl.conf" >> /root/Desktop/BackupB4Hardening/output.txt
sleep 1
echo "net.ipv4.tcp_wmem = 100000000   100000000       100000000
net.ipv4.tcp_rmem = 100000000   100000000       100000000
net.core.netdev_max_backlog = 600000
net.core.somaxconn=4096
net.core.optmem_max = 640000000
net.ipv4.tcp_app_win = 31
net.ipv4.tcp_adv_win_scale = 2
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.udp_wmem_min = 16384
kernel.panic_on_io_nmi = 1
kernel.sysrq = 1
kernel.panic = 10
kernel.panic_on_oops = 1
kernel.unknown_nmi_panic = 1
kernel.panic_on_unrecovered_nmi = 1
vm.pagecache_limit_mb = 4096
vm.pagecache_limit_ignore_dirty = 2
kernel.shmmax = 9223372036854775807
kernel.sem = 1250 256000 100 8192
kernel.shmall = 1152921504606846720
vm.max_map_count=607000000
fs.file-max=20000000
vm.memory_failure_early_kill=1"

echo "net.ipv4.tcp_wmem = 100000000   100000000       100000000
net.ipv4.tcp_rmem = 100000000   100000000       100000000
net.core.netdev_max_backlog = 600000
net.core.somaxconn=4096
net.core.optmem_max = 640000000
net.ipv4.tcp_app_win = 31
net.ipv4.tcp_adv_win_scale = 2
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.udp_wmem_min = 16384
kernel.panic_on_io_nmi = 1
kernel.sysrq = 1
kernel.panic = 10
kernel.panic_on_oops = 1
kernel.unknown_nmi_panic = 1
kernel.panic_on_unrecovered_nmi = 1
vm.pagecache_limit_mb = 4096
vm.pagecache_limit_ignore_dirty = 2
kernel.shmmax = 9223372036854775807
kernel.sem = 1250 256000 100 8192
kernel.shmall = 1152921504606846720
vm.max_map_count=607000000
fs.file-max=20000000
vm.memory_failure_early_kill=1" >> /root/Desktop/BackupB4Hardening/output.txt

echo "net.ipv4.tcp_wmem = 100000000   100000000       100000000" >> /etc/sysctl.conf
echo "net.ipv4.tcp_rmem = 100000000   100000000       100000000" >> /etc/sysctl.conf
echo "net.core.netdev_max_backlog = 600000"  >> /etc/sysctl.conf
echo "net.core.somaxconn=4096"  >> /etc/sysctl.conf
echo "net.core.optmem_max = 640000000" >> /etc/sysctl.conf
echo "net.ipv4.tcp_app_win = 31" >> /etc/sysctl.conf
echo "net.ipv4.tcp_adv_win_scale = 2" >> /etc/sysctl.conf
echo "net.ipv4.tcp_no_metrics_save = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_moderate_rcvbuf = 1" >> /etc/sysctl.conf
echo "net.ipv4.udp_wmem_min = 16384" >> /etc/sysctl.conf
echo "kernel.panic_on_io_nmi = 1" >> /etc/sysctl.conf
echo "kernel.sysrq = 1" >>  /etc/sysctl.conf
echo "kernel.panic = 10" >> /etc/sysctl.conf
echo "kernel.panic_on_oops = 1"  >> /etc/sysctl.conf
echo "kernel.unknown_nmi_panic = 1 " >> /etc/sysctl.conf
echo "kernel.panic_on_unrecovered_nmi = 1"  >> /etc/sysctl.conf
echo "vm.pagecache_limit_mb = 4096" >> /etc/sysctl.conf
echo "vm.pagecache_limit_ignore_dirty = 2" >> /etc/sysctl.conf
echo "kernel.shmmax = 9223372036854775807" >> /etc/sysctl.conf
echo "kernel.sem = 1250 256000 100 8192" >> /etc/sysctl.conf
echo "kernel.shmall = 1152921504606846720" >> /etc/sysctl.conf
echo "vm.max_map_count=607000000" >> /etc/sysctl.conf
echo "fs.file-max=20000000" >> /etc/sysctl.conf
echo "vm.memory_failure_early_kill=1" >> /etc/sysctl.conf

#########################################################################################################################
echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################"
sleep 3
#cp -rpf /etc/security/limits.conf /root/Desktop/BackupB4Hardening/limits.conf
sleep 2
echo "@sapsys          soft    nofile          32800 >> /etc/security/limits.conf
@sapsys          hard    nofile          32800  >> /etc/security/limits.conf
@sdba            soft    nofile          32800 >> /etc/security/limits.conf
@sdba            hard    nofile          32800 >> /etc/security/limits.conf
@dba             soft    nofile          32800  >> /etc/security/limits.conf
@dba             hard    nofile          32800 >> /etc/security/limits.conf" >> /root/Desktop/BackupB4Hardening/output.txt

echo "@sapsys          soft    nofile          32800" >> /etc/security/limits.conf
echo "@sapsys          hard    nofile         32800"  >> /etc/security/limits.conf
echo "@sdba            soft    nofile          32800" >> /etc/security/limits.conf
echo "@sdba            hard    nofile          32800" >> /etc/security/limits.conf
echo "@dba             soft    nofile          32800"  >> /etc/security/limits.conf
echo "@dba             hard    nofile          32800" >> /etc/security/limits.conf

echo "@sapsys          soft    nofile          32800 >> /etc/security/limits.conf
@sapsys          hard    nofile          32800  >> /etc/security/limits.conf
@sdba            soft    nofile          32800 >> /etc/security/limits.conf
@sdba            hard    nofile          32800 >> /etc/security/limits.conf
@dba             soft    nofile          32800  >> /etc/security/limits.conf
@dba             hard    nofile          32800 >> /etc/security/limits.conf"

##############################################################################################################
#echo -e "Adding Parameters in /etc/sysctl.conf"
#echo -e "Adding Parameters in /etc/sysctl.conf" >> /root/Desktop/BackupB4Hardening/output.txt
#sleep 2
#echo -e "kernel.exec-shield = 1" >> /root/Desktop/BackupB4Hardening/output.txt
#echo -e "kernel.randomize_va_space = 2" >>  /root/Desktop/BackupB4Hardening/output.txt
#/etc/sysctl.conf
#cat << 'EOF' >> /etc/sysctl.conf
#/bin/sysctl -p
# CIS Benchmark Adjustments
#kernel.exec-shield = 1
#kernel.randomize_va_space = 2
#EOF
/sbin/sysctl -p /etc/sysctl.conf
echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################################"
sleep 2
echo -e "Adding DNS  entries in /etc/resolv.conf"
echo -e "Adding DNS  entries in /etc/resolv.conf" >> /root/Desktop/BackupB4Hardening/output.txt
#cp -rpf /etc/resolv.conf /root/Desktop/BackupB4Hardening/resolv.conf
sleep 2
echo "nameserver     10.66.15.201" >> /root/Desktop/BackupB4Hardening/output.txt
echo "nameserver     10.66.9.204 " >> /root/Desktop/BackupB4Hardening/output.txt
echo "nameserver     10.66.15.201" > /etc/resolv.conf
echo "nameserver     10.66.9.204 " >> /etc/resolv.conf


######################Bashrc Edited######################################
#echo -e "Create /etc/bashrc & change Umask Value"
#echo -e "Create /etc/bashrc & change Umask Value" >> /root/Desktop/BackupB4Hardening/output.txt
#sleep 2
#echo "umask 022" >> /etc/bashrc
#touch /etc/bashrc
#echo "umask 022" /etc/bashrc


#######################yum configured####################################


#cd /etc/yum.repos.d/
#mv * /root/Desktop/BackupB4Hardening/backup.repo.prehard
#echo "Files have been copied to /root/Desktop/BackupB4Hardening " >>${HARD_LOG}
#
#touch client.repo
#
#echo "[client]
#name =  Repository
#baseurl=http://sidclinrepo06.ril.com/repo
##baseurl=http://sidclinrepo05.ril.com/rhelupdate5	
#gpgcheck=0
#enabled=1 " >>/etc/yum.repos.d/client.repo
#
#/usr/bin/yum clean all 
#/usr/bin/yum repolist
##/usr/bin/yum list
#
#
##########################################################################

##########################################################################
#mount -o remount,nodev /tmp
#mount -o remount,nosuid /tmp
#mount -o remount,noexec /tmp
#mount -o remount,nodev /home
#mount -o remount,nodev /dev/shm
#mount -o remount,nosuid /dev/shm
#mount -o remount,noexec /dev/shm
####edit the line with Follwing value###

#sed -i '/tmp\s/ s/defaults/Noexec,Nosuid,Nodev/' /etc/fstab 
#sed -i '/tmp\s/ s/acl,user_xattr/Noexec,Nosuid,Nodev/' /etc/fstab
#echo "All the activities are done by this script has been logged into $HARD_LOG"

echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################################"
sleep 2

#################Grub Passwd ###########################################################################################
echo -e "Setting GRUB Password"
echo -e "Setting GRUB Password"  >> /root/Desktop/BackupB4Hardening/output.txt
for i in `grep password /boot/grub/grub.conf` ; do sed -i /"$i"/d /boot/grub/grub.conf ; done > 2&>1
printf 'password --md5 $1$lPYJv1$0Pzi..DK6Qy4GurghbWEd/' >>/boot/grub/grub.conf

echo "############################################" >> /root/Desktop/BackupB4Hardening/output.txt
echo "############################################################"
sleep 2
#rm -rf root
