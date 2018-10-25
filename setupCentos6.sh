yum update -y
yum install epel-release -y
yum install nano wget unzip libsodium net-tools -y

chmod +x /etc/rc.d/rc.local
systemctl enable rc-local
systemctl start rc-local
systemctl status rc-local


rpm -ivh http://soft.91yun.org/ISO/Linux/CentOS/kernel/kernel-firmware-2.6.32-504.3.3.el6.noarch.rpm
rpm -ivh http://soft.91yun.org/ISO/Linux/CentOS/kernel/kernel-2.6.32-504.3.3.el6.x86_64.rpm --force

reboot
