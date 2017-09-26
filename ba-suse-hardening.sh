#!/bin/sh
server=`ifconfig | awk -F':' '/inet addr/&&!/127.0.0.1/{split($2,_," ");print _[1]}'`
HARD_LOG="/var/log/${server}_hard_log"
#echo -n "Please Enter Your Name: "
#read NAME
#echo ":Enter your Name" $NAME >>${HARD_LOG}
echo "Please wait.....Hardening is in progess"
echo " Creating Directory Called /etc/BackupSystemFiles for Backup of critical files and files copying are in progress" >> ${HARD_LOG}
mkdir /etc/BackupSystemFiles 
cd / 
tar -cvf /etc/BackupSystemFiles/etc.tar etc &>/dev/null
sleep 10
echo "Files have been copied to /etc/BackupSystemFiles " >>${HARD_LOG}
#######Lock the Unneccessary Accounts########
echo "Locking the Uneccessary Accounts">>${HARD_LOG}
cp -p /etc/passwd /etc/BackupSystemFiles/passwd.prehard
for USERID in rpc rpcuser lp named dns mysql postgres squid news netdump
do
usermod -L -s /sbin/nologin $USERID &>/dev/null
done
echo "********************************************************************************">> ${HARD_LOG}

#######Block System Accounts#######
cp -p /etc/passwd /etc/BackupSystemFiles/passwd.prehard
for NAME in `cut -d: -f1 /etc/passwd`;
do
MyUID=`id -u $NAME`
if [ $MyUID -lt 500 -a $NAME != 'root' ]; then
usermod -L -s /sbin/nologin $NAME
fi
done
######Verify passwd, shadow and group file permissions#######
cd /etc
ls -l > /etc/BackupSystemFiles/etc.files

######Verify that no UID 0 Account exists Other than root######
echo "********************************************************************************">> ${HARD_LOG}
awk -F: '($3 == 0) { print "UID 0 Accounts are Below. Please do block if its not neccessary\n" $1 }' /etc/passwd>> ${HARD_LOG}
echo "********************************************************************************">> ${HARD_LOG}

######Banner#####
echo "Updating the banner in /root/banner file" >> ${HARD_LOG}
cat > /root/banner << EOF
##################################################################
|This system is for the use of authorized users only. 		 |
|Individuals using this computer system without authority, or in |
|excess of their authority, are subject to having all of their   |
|activities on this system monitored and recorded by system      |
|personnel. 							 |
|In the course of monitoring individuals improperly using this   |
|system, or in the course of system maintenance, the activities  |
|of authorized users may also be monitored.                      |
|Anyone using this system expressly consents to such monitoring  |
|and is advised that if such monitoring reveals possible         |
|evidence of criminal activity, system personnel may provide the |
|evidence of such monitoring to law enforcement officials.       |
##################################################################
EOF
cat /root/banner
cp -p /etc/issue.net /etc/BackupSystemFiles/issue.net.prehard
cp -p /etc/issue /etc/BackupSystemFiles/issue.prehard
cat /root/banner > /etc/issue.net
cat /root/banner > /etc/issue
cat /root/banner > /etc/motd 

###############################Default RRunlevel #######################################
sed -i 's/id:5:initdefault:/id:3:initdefault:/g' /etc/inittab
sed -i 's/ca::ctrlaltdel:/#ca::ctrlaltdel:/g' /etc/inittab
#####ssh configuration######
echo "Configuring SSH service" >>${HARD_LOG}
cd /etc/ssh
cp -p ssh_config /etc/BackupSystemFiles/ssh_config.prehard
cp -p sshd_config /etc/BackupSystemFiles/sshd_config.prehard
#sed -e 's/#PermitRootLogin yes/PermitRootLogin no/g' sshd_config >>sshd_config1
cp -p sshd_config sshd_config.before
mv sshd_config1 sshd_config
echo Banner /root/banner >> /etc/ssh/sshd_config
service sshd restart
#########################################################################################333

echo "********************************************************************************">> ${HARD_LOG}
echo "Setting Password Expiry Time for users ..." >> ${HARD_LOG}
cp /etc/login.defs /etc/BackupSystemFiles/login.defs.prehard
cd /etc
sed -e 's/99999/45/g' login.defs > login.defs1
cp login.defs login.defs.before
mv login.defs1 login.defs
/bin/sed -e 's/PASS_MIN_LEN\s5/PASS_MIN_LEN\t8/g' login.defs > login.defs1
cp login.defs login.defs.before
mv login.defs1 login.defs
echo "********************************************************************************">> ${HARD_LOG}
######Set Daemon Umask######
cd /etc/init.d
cp -p functions /etc/BackupSystemFiles/functions.prehard
# edit the line with umask
#sed -e 's/umask 022/umask 027/g' functions >>functions1
cp -p functions functions.before
mv functions1 functions
echo "All the activities are done by this script has been logged into $HARD_LOG"
###################################################################################

cd /etc/
touch bashrc
echo "umask 022" >> /etc/bashrc
cp -p bashrc /etc/BackupSystemFiles/bashrc.prehard
# edit the line with umask
#sed -e 's/umask 002/umask 022/g' bashrc >>bashrc1
#cp -p bashrc bashrc.before
#mv bashrc1 bashrc
echo "All the activities are done by this script has been logged into $HARD_LOG"

#####################Set Profile Umask #############################################

echo "umask 022" >> /root/.bash_profile

source /root/.bash_profile


echo "#======================================================================#"
echo
echo " END OF THE SCRIPT "
echo
echo "#======================================================================#" 

##############################################################################################
#######Confirm Permissions On System Log files######
/bin/ls  -l > /etc/BackupSystemFiles/system.logfiles
/bin/chmod 751 /var/log
cd /var/log

####Restrict Root Logins To System Console By adding the entry called console in the file /etc/securetty#####

echo "Restricting root Logins to the System Console By adding the entry called console in the file /etc/securetty" >> ${HARD_LOG}
cp -p /etc/securetty /etc/BackupSystemFiles/securetty.prehard
#for i in 'seq 1 6'; do
#echo tty$i >> /etc/securetty
#done
#for i in 'seq 1 11'; do
#echo vc/$i >> /etc/securetty
#done
#echo console >> /etc/securetty
chown root:root /etc/securetty
chmod 0600 /etc/securetty
echo "Protocol 2" >> /etc/ssh/sshd_config
echo "ENCRYPT_METHOD	SHA512" >> /etc/login.defs
echo "PASS_MIN_LEN	8" >> /etc/login.defs
chmod 0644 /var/log/lastlog
###################PAM Configuration setting ##########################################

cp /etc/pam.d/su /etc/BackupSystemFiles/
echo "Updating file  /etc/pam.d/su"
cp /etc/pam.d/su /etc/BackupSystemFiles/
/bin/sed -r 's/^#(.*required\s+pam_wheel\.so use_uid.*)/\1/' /etc/pam.d/su > /etc/pam.d/su1
mv /etc/pam.d/su1 /etc/pam.d/su
/bin/sed -r 's/^#(.*required\s+pam_wheel\.so use_uid.*)/\1/' /etc/pam.d/su
echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su

###########################################################################################
###########################Services Should be on ##########################################

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


###################Services Should be stop/save/restart####################################

/etc/init.d/xinetd stop
/etc/init.d/ntp restart
/etc/init.d/auditd restart
#/etc/init.d/sshd restart
#/etc/init.d/ntpdate stop

###########################################################################################

################# The following services should be off ####################################
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

#/sbin/chkconfig --level 0123456 ntpdate off
#/sbin/chkconfig --level 0123456  sysstat off 


#configure hosts.deny and hosts.allow 



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


###########################Permission and change and Modify owner and group###############

chown root:root /etc/grub.conf
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

###########################################################################################

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
chmod 0644 /var/log/wtmp
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
chmod 0600 /etc/securetty
chmod 0644 /var/spool/cron

 

#################at.allow############################################################

/bin/touch /etc/cron.allow
/bin/touch /etc/at.allow
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
chmod 0400 /etc/cron.allow
cp /etc/cron.deny /etc/BackupSystemFiles/cron.deny.prehard
cp /etc/at.deny /etc/BackupSystemFiles/at.deny.prehard

echo "Removing /etc/cron.deny"
/bin/rm -f /etc/cron.deny
/bin/rm -f /etc/at.deny

#==============================================#

touch /etc/security/console.perms.d/50-default.perms
chmod 0600 /etc/security/console.perms.d/50-default.perms

#==============================================#


chown root:root /etc/at.allow 
chmod 0400 /etc/at.allow

chmod -s /bin/ping6 /bin/cgexec /bin/mount /bin/ping /bin/umount /sbin/netreport /sbin/unix_chkpwd /sbin/mount.nfs /sbin/pam_timestamp_check
chmod -s /usr/sbin/usernetctl /usr/sbin/postdrop /usr/sbin/postqueue /usr/sbin/userhelper /usr/libexec/polkit-1/polkit-agent-helper-1 /usr/libexec/abrt-action-install-debuginfo-to-abrt-cache /usr/libexec/pt_chown /usr/libexec/utempter/utempter /usr/libexec/openssh/ssh-keysign /usr/bin/pkexec /usr/bin/sudoedit /usr/bin/staprun /usr/bin/passwd /usr/bin/write /usr/bin/newgrp /usr/bin/ssh-agent /usr/bin/sudo /usr/bin/chfn /usr/bin/at /usr/bin/gpasswd /usr/bin/chage /usr/bin/ksu /usr/bin/wall /usr/bin/locate /usr/bin/chsh /usr/bin/crontab
 
######chmod -s /lib64/dbus-1/dbus-daemon-launch-helper


#########################configure rsyslog file ##########################

cp /etc/rsyslog.conf /etc/BackupSystemFiles/rsyslog.conf.prehard
echo "# The authpriv file has restricted access." >> /etc/rsyslog.conf
echo "auth.*,user.*             /var/log/messages" >> /etc/rsyslog.conf


#chmod 0644 /etc/at.allow

cp /etc/audit/auditd.conf /etc/audit/audit.conf


#chmod 0400 /etc/gshadow

#chmod 0400 /etc/shadow


#chmod 0400 /etc/at.allow
#chmod 0400 /etc/inittab	

#chmod 0600 /opt/log/messages /opt/log/lastlog

#Copy password of /etc/grub.cong
#sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config
#sed -i "/SINGLE/s/sushell/sulogin/" /etc/sysconfig/init




############TO BE ADDED IN SCRIPT#################################################

cp /etc/sysctl.conf /etc/sysctl.conf.org
cp /etc/pam.d/system-auth /etc/pam.d/system-auth.org
cp /etc/grub.conf /etc/grub.conf.org
cp  /etc/securetty /etc/securetty.org

rpm -ivh aide-0.14-3.el6.x86_64.rpm

crontab -l root 

echo "0 5 * * * /usr/sbin/aide --check" >> root

crontab root

crontab -l


#configure hosts.deny and hosts.allow 

#configure nousb in /etc/grub.conf
touch /etc/security/console.perms.d/50-default
#======================================================================#

configure ntp.conf
sed -i 's/server 0.rhel.pool.ntp.org iburst/server dc1ntp.idc.ril.com /' /etc/ntp.conf
sed -i 's/server 1.rhel.pool.ntp.org iburst/server idc1ntp1.idc.ril.com /' /etc/ntp.conf
sed -i 's/server 2.rhel.pool.ntp.org iburst/#server 2.rhel.pool.ntp.org iburst/' /etc/ntp.conf
sed -i 's/server 3.rhel.pool.ntp.org iburst/#server 3.rhel.pool.ntp.org iburst/' /etc/ntp.conf

/usr/sbin/ntpq -p

##################################configure sysctl.conf################################
echo "##########################ADDITIONAL LINES#######################################" >>/etc/sysctl.conf

echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
echo "net.ipv4.icmp_igNore_bogus_error_messages= 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 4096" >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf 



/etc/sysctl.conf
cat << 'EOF' >> /etc/sysctl.conf

# CIS Benchmark Adjustments
kernel.exec-shield = 1
kernel.randomize_va_space = 2

EOF


/sbin/sysctl -p /etc/sysctl.conf


########################Resolv.conf######################################

echo "nameserver     10.66.15.201" >> /etc/resolv.conf
echo "nameserver     10.66.9.204 " >> /etc/resolv.conf

######################Bashrc Edited######################################
touch /etc/bashrc
echo "umask 022" /etc/bashrc

#########################################################################

#######################yum configured####################################


#cd /etc/yum.repos.d/
#mv * /etc/BackupSystemFiles/backup.repo.prehard
#echo "Files have been copied to /etc/BackupSystemFiles " >>${HARD_LOG}
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

cd /etc/
cp -p fstab /etc/BackupSystemFiles/fstab.prehard
####edit the line with Follwing value###

sed -i '/tmp\s/ s/defaults/Noexec,Nosuid,Nodev/' /etc/fstab 

echo "All the activities are done by this script has been logged into $HARD_LOG"


#################Grub Passwd #######################################################

cp /etc/grub.conf /etc/grub.conf.org
printf 'password --md5 $1$lPYJv1$0Pzi..DK6Qy4GurghbWEd/' >>/etc/grub.conf



#[root@SIDCLINUX Packages]# ed /etc/grub.conf << END
#> g/audit=1/s///g
#> g/kernel/s/$/ audit=1/
#> w
#> q
#> END

####################################################################################


#echo "umask 027"  /etc/sysconfig/init


#############TO BE ADDED IN SCRIPT#################################################

cp /etc/sysctl.conf /etc/sysctl.conf.org
#cp /etc/pam.d/system-auth /etc/pam.d/system-auth.org
cp /etc/grub.conf /etc/grub.conf.org
cp /etc/securetty /etc/securetty.org
cp /etc/audit/auditd.conf /etc/audit/auditd.conf.org
cp /etc/audit/audit.rules /etc/audit/audit.rules.org


###########################################################################

#configure nousb in /etc/grub.conf
#touch /etc/security/console.perms.d/50-default
#
#echo "##########################ADDITIONAL LINES###############################################" >>//etc/security/limits.conf
#echo "*                soft    core            unlimited" >>//etc/security/limits.conf



#===========================================================


#echo "admin    ALL=(ALL)       ALL" >>/etc/sudoers



#AllowUsers admin root
#nest+dome-lessen

