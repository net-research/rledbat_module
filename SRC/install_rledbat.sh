#!/usr/bin/env bash

# to change the rledbat port, change also rledbat_receive.c
PORT=49000

# #(https://serverfault.com/questions/230804/how-gro-generic-receive-offload-works-on-more-advanced-nics)
# sudo ethtool -K eth0 gro off 

# # to avoid checksum failures
# sudo ethtool --offload  eth0  rx off  tx off

# ##(https://serverfault.com/questions/230804/how-gro-generic-receive-offload-works-on-more-advanced-nics)
# sudo ethtool -K eth1 gro off 

# ## to avoid checksum failures
# sudo ethtool --offload  eth1 rx off  tx off

# ethtool -K ethX sg off

# sysctl -w net.ipv4.tcp_window_scaling=1 
#to activate WS. NO WS sysctl -w net.ipv4.tcp_window_scaling=0 defaukt WS=7
echo 'Disable windows scaling'
echo
echo
sysctl -w net.ipv4.tcp_window_scaling=1
echo 
echo
# clean rledbat logs
sudo tee /var/log/kern.log </dev/null
sudo tee /var/log/syslog </dev/null


sudo iptables -t mangle -F #clean the iptables rules
modprobe -q -r xt_TCPWIN #eliminate the already charged write module
sudo rmmod xt_TCPWIN
sudo rmmod rledbat_receive #eliminate charged read module


echo 'Compiling (if needed) and loading modules'
echo
cd /home/ledbat/SRC
make #compile read module
sudo insmod rledbat_receive.ko #upload the read module

#to compile the write module, you have to loaded the read module first
cd  kernel #cd write module
make #compile write module
cp xt_TCPWIN.ko /lib/modules/3.13.0-24-generic/kernel/net/netfilter #cp module in iptables extension
modprobe xt_TCPWIN #upload write module
iptables -t mangle -I OUTPUT -p tcp --tcp-flags ACK ACK --sport ${PORT} -j TCPWIN --tcpwin-set 0 #set iptables rule for write module

echo
echo
echo 'rledbat modules loaded'
