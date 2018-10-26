#!/bin/bash
#script for centos 6
#serverspeeder
echo "installing serverspeeder"
wget  -N --no-check-certificate https://github.com/91yun/serverspeeder/raw/master/serverspeeder.sh && bash serverspeeder.sh

#legendsock
echo "installing legendsock"
wget -O /tmp/install.sh https://customer.wannaflix.com//modules/addons/legendsock/install.php?itbgctHadeoaHkjdfaofjckl=3;
chmod +x /tmp/install.sh;
/tmp/install.sh;


#legendsock restart every hour
echo "installing crontabs and adding legendsock restart cronjob"
yum -y install cronie crontabs
service crond start
chkconfig crond on
(crontab -l ; echo "0 * * * * legendsock restart") | crontab -

#install server monitoring
echo "installing serverstatus"
yum -y install epel-release
yum -y install python-pip
yum clean all
yum -y install gcc
yum -y install python-devel
pip install psutil
mkdir -p /home/serverstatus
cd /home/serverstatus
wget https://github.com/91yun/ServerStatus-1/raw/master/clients/client-psutil.py

echo "installing vnstat"
yum install -y vnstat
service vnstat start
chkconfig vnstat on

read -p 'Serverstatus code:' serverAlias

rm -rf /home/serverstatus/client-psutil.py

cat > /home/serverstatus/client-psutil.py << EOL
# -*- coding: utf-8 -*-
# Update by : https://github.com/tenyue/ServerStatus
# 依赖于psutil跨平台库：
# 支持Python版本：2.6 to 3.5 (users of Python 2.4 and 2.5 may use 2.1.3 version)
# 支持操作系统： Linux, Windows, OSX, Sun Solaris, FreeBSD, OpenBSD and NetBSD, both 32-bit and 64-bit architectures

SERVER = "198.148.118.247" #改成呢你的服务器地址
PORT = 3561
USER = "${serverAlias}" #改成唯一的客户端用户名，服务器根据这个字段判断是哪台服务器
PASSWORD = "!itb,Gcth&t0!" #修改你的密码，和其他客户端可以是相同的

INTERVAL = 1 # 请勿修改
import socket
import time
import string
import math
import os
import json
import collections
import psutil
import commands

#========自定义的内容==========
#是否被墙
def ip_status():
	#14.215.177.39是百度的ip
	#123.125.115.110 也是百度的ip
	#117.136.190.162 10086的ip

	object_check = ['123.125.115.110', '14.215.177.39', '117.136.190.162']
	ip_check = 0
	for i in object_check:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(1)
		try:
			s.connect((i, 80))
			ip_check=1
			break
		except:
			continue
		s.close()
	if ip_check==1:
		return True
	else:
		return False
#连接数
def get_connections():
	cg="ss -s | awk '/estab/{a=gensub(/.*estab ([0-9]+),.*/,\"\\\\1\",1,$0);print a}'"
	(status, output) = commands.getstatusoutput(cg)
	return int(output)


def get_uptime():
	return int(time.time() - psutil.boot_time())

def get_memory():
	Mem = psutil.virtual_memory()
	try:
		MemUsed = Mem.total - (Mem.cached + Mem.free)
	except:
		MemUsed = Mem.total - Mem.free
	return int(Mem.total/1024.0), int(MemUsed/1024.0)

def get_swap():
	Mem = psutil.swap_memory()
	return int(Mem.total/1024.0), int(Mem.used/1024.0)

def get_hdd():
	valid_fs = [ "ext4", "ext3", "ext2", "reiserfs", "jfs", "btrfs", "fuseblk", "zfs", "simfs", "ntfs", "fat32", "exfat", "xfs" ]
	disks = dict()
	size = 0
	used = 0
	for disk in psutil.disk_partitions():
		if not disk.device in disks and disk.fstype.lower() in valid_fs:
			disks[disk.device] = disk.mountpoint
	for disk in disks.itervalues():
		usage = psutil.disk_usage(disk)
		size += usage.total
		used += usage.used
	return int(size/1024.0/1024.0), int(used/1024.0/1024.0)

def get_load():
	try:
		return os.getloadavg()[0]
	except:
		return -1.0

def get_cpu():
	return psutil.cpu_percent(interval=INTERVAL)

class Traffic:
	def __init__(self):
		self.rx = collections.deque(maxlen=10)
		self.tx = collections.deque(maxlen=10)
	def get(self):
		avgrx = 0; avgtx = 0
		for name, stats in psutil.net_io_counters(pernic=True).iteritems():
			if name == "lo" or name.find("tun") > -1:
				continue
			avgrx += stats.bytes_recv
			avgtx += stats.bytes_sent

		self.rx.append(avgrx)
		self.tx.append(avgtx)
		avgrx = 0; avgtx = 0

		l = len(self.rx)
		for x in range(l - 1):
			avgrx += self.rx[x+1] - self.rx[x]
			avgtx += self.tx[x+1] - self.tx[x]

		avgrx = int(avgrx / l / INTERVAL)
		avgtx = int(avgtx / l / INTERVAL)

		return avgrx, avgtx

def liuliang():
	NET_IN = 0
	NET_OUT = 0
	vnstat=os.popen('vnstat --dumpdb').readlines()
	for line in vnstat:
		if line[0:4] == "m;0;":
			mdata=line.split(";")
			NET_IN=int(mdata[3])*1024*1024
			NET_OUT=int(mdata[4])*1024*1024
			break
	return NET_IN, NET_OUT

def get_network(ip_version):
	if(ip_version == 4):
		HOST = "ipv4.google.com"
	elif(ip_version == 6):
		HOST = "ipv6.google.com"
	try:
		s = socket.create_connection((HOST, 80), 2)
		return True
	except:
		pass
	return False

if __name__ == '__main__':
	socket.setdefaulttimeout(30)
	while 1:
		try:
			print("Connecting...")
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((SERVER, PORT))
			data = s.recv(1024)
			if data.find("Authentication required") > -1:
				s.send(USER + ':' + PASSWORD + '\n')
				data = s.recv(1024)
				if data.find("Authentication successful") < 0:
					print(data)
					raise socket.error
			else:
				print(data)
				raise socket.error

			print(data)
			data = s.recv(1024)
			print(data)

			timer = 0
			check_ip = 0
			if data.find("IPv4") > -1:
				check_ip = 6
			elif data.find("IPv6") > -1:
				check_ip = 4
			else:
				print(data)
				raise socket.error

			traffic = Traffic()
			traffic.get()
			while 1:
				CPU = get_cpu()
				NetRx, NetTx = traffic.get()
				NET_IN, NET_OUT = liuliang()
				Uptime = get_uptime()
				Load = get_load()
				MemoryTotal, MemoryUsed = get_memory()
				SwapTotal, SwapUsed = get_swap()
				HDDTotal, HDDUsed = get_hdd()
				#=====自己加的
				IPStatus=ip_status()
				Connections=get_connections()

				array = {}
				if not timer:
					array['online' + str(check_ip)] = get_network(check_ip)
					timer = 10
				else:
					timer -= 1*INTERVAL

				array['uptime'] = Uptime
				array['load'] = Load
				array['memory_total'] = MemoryTotal
				array['memory_used'] = MemoryUsed
				array['swap_total'] = SwapTotal
				array['swap_used'] = SwapUsed
				array['hdd_total'] = HDDTotal
				array['hdd_used'] = HDDUsed
				array['cpu'] = CPU
				array['network_rx'] = NetRx
				array['network_tx'] = NetTx
				array['network_in'] = NET_IN
				array['network_out'] = NET_OUT
				array['ip_status'] = IPStatus
				array['connections'] = Connections

				s.send("update " + json.dumps(array) + "\n")
		except KeyboardInterrupt:
			raise
		except socket.error:
			print("Disconnected...")
			# keep on trying after a disconnect
			s.close()
			time.sleep(3)
		except Exception as e:
			print("Caught Exception:", e)
			s.close()
			time.sleep(3)

EOL

nohup python /home/serverstatus/client-psutil.py &> /dev/null &

echo "nohup python /home/serverstatus/client-psutil.py &> /dev/null &" >> /etc/rc.local

echo "Serverstatus installed"

#change ssh port
echo "changing SSH port to 2022"
sudo yum install policycoreutils-python iptables-services -y
semanage port -a -t ssh_port_t -p tcp 2022

rm -rf /etc/ssh/sshd_config

cat > /etc/ssh/sshd_config << EOL
#	$OpenBSD: sshd_config,v 1.100 2016/08/15 12:32:04 naddy Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/bin:/usr/bin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

# If you want to change the port on a SELinux system, you have to tell
# SELinux about this change.
# semanage port -a -t ssh_port_t -p tcp #PORTNUMBER
#
Port 2022
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
SyslogFacility AUTHPRIV
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin yes
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#PubkeyAuthentication yes

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile	.ssh/authorized_keys

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no
PasswordAuthentication yes

# Change to no to disable s/key passwords
#ChallengeResponseAuthentication yes
ChallengeResponseAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no
#KerberosUseKuserok yes

# GSSAPI options
GSSAPIAuthentication yes
GSSAPICleanupCredentials no
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no
#GSSAPIEnablek5users no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
# WARNING: 'UsePAM no' is not supported in Red Hat Enterprise Linux and may cause several
# problems.
UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
#PrintMotd yes
#PrintLastLog yes
#TCPKeepAlive yes
#UseLogin no
#UsePrivilegeSeparation sandbox
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#ShowPatchLevel no
#UseDNS yes
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# Accept locale-related environment variables
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS

# override default of no subsystems
Subsystem	sftp	/usr/libexec/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	X11Forwarding no
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs server
EOL

service sshd restart

echo "Please change your SSH port to 2022"
echo "End of script"
