""" RouteFlow autoconfig

authors: Zeng Pengcheng (zpcpromac@gmail.com)

date: 2014.03.31
"""

### note: switch should be less than 230
### rf.conf: host, hX should start by "h" and followed by a number
###          switch, sX should start by "s" and followed by a number
###rftestName should be started with letters or "_".
import os, sys

class Topology:
    def __init__(self, rftestName, confFileName):
        self.confFileName = confFileName
        self.hosts = []
        self.switches = []
        self.connections = []
        self.rftestName = rftestName
        self.switch_port = {}
        self.switch_port_address = {}
        if not os.path.exists(self.rftestName):
            os.makedirs(self.rftestName)
        self.readConf()

    def readConf(self):
        fin = open(self.confFileName, 'r')
        try:
            fin.readline()
            hosts = fin.readline()
            for item in hosts.split(","):
                host = item.strip()
                if host not in self.hosts:
                    self.hosts.append(host)
            fin.readline()
            switches = fin.readline()
            for item in switches.split(","):
                switch = item.strip()
                if switch not in self.switches:
                    self.switches.append(switch)
            fin.readline()
            for line in fin.readlines():
                a,b = line.split(" ")
                a = a.strip()
                b = b.strip()
                if (a in self.hosts or a in self.switches) and (b in self.hosts or b in self.switches):
                    if a in self.hosts and b in self.hosts:
                        print "connection error1: "+line
                        sys.exit(1)
                    else:
                        for connection in self.connections:
                            if ( connection[0] == a and connection[1] == b ) or ( connection[1] == a and connection[0] == b ):
                                print "connection exist: "+line
                                sys.exit(1)
                        self.connections.append((a,b))
                else:
                    print "connection error2: "+line
                    sys.exit(1)
            for switch in self.switches:
                self.switch_port[switch] = 0
                self.switch_port_address[switch] = []
            for connection in self.connections:
                if connection[0] in self.switches:
                    self.switch_port[connection[0]] += 1
                if connection[1] in self.switches:
                    self.switch_port[connection[1]] += 1
            i = 0
            for connection in self.connections:
                if connection[0] in self.switches and connection[1] in self.switches:
                    i += 1
                    prefix = str(i)+".0.0."
                    self.switch_port_address[connection[0]].append(prefix)
                    self.switch_port_address[connection[1]].append(prefix)
                else:
                    if connection[0] in self.hosts:
                        self.switch_port_address[connection[1]].append("172.31."+str(self.hosts.index(connection[0])+1)+".")
                    else:
                        self.switch_port_address[connection[0]].append("172.31."+str(self.hosts.index(connection[1])+1)+".")
        except:
            print "Conf File Format Error"
            exit
        finally:
            fin.close()

    def generateMNTopoFile(self):
        fileName = "topo-"+str(len(self.switches))+"sw-"+str(len(self.hosts))+"host.py"
        fout = open(self.rftestName+"/"+fileName, 'w')
        
        className = self.rftestName

        fout.write('''from mininet.topo import Topo

class %s(Topo):
    "RouteFlow Setup"

    def __init__( self, enable_all = True ):
        "Create custom topo."

        Topo.__init__( self )
        ''' %(className))

        hostIndex = 0
        for host in self.hosts:
            hostIndex += 1
            fout.write('''
        %s = self.addHost("%s",
                          ip="172.31.%d.100/24",
                          defaultRoute="gw 172.31.%d.1")
                ''' %(host, host, hostIndex, hostIndex))
        
        for switch in self.switches:
            fout.write('''
        %s = self.addSwitch("%s")
                ''' %(switch, switch))

        for connection in self.connections:
            fout.write('''
        self.addLink(%s, %s)
            ''' %(connection[0],connection[1]))

        fout.write('''
topos = { '%s': ( lambda: %s() ) }
''' %(className,className))
        fout.close()


    def generateIpconfFile(self):
        fileName = "ipconf"
        fout = open(self.rftestName+"/"+fileName, 'w')
        hostIndex = 0
        for host in self.hosts:
            hostIndex += 1
            fout.write('''%s route add default gw 172.31.%d.1
''' % (host, hostIndex))
        fout.close()

    def generateRftestFile(self):
        fileName = self.rftestName
        fout = open(self.rftestName+"/"+fileName, 'w')
        fout.write('''#!/bin/bash

if [ "$EUID" != "0" ]; then
  echo "You must be root to run this script."
  exit 1
fi

SCRIPT_NAME="%s"
LXCDIR=/var/lib/lxc
MONGODB_CONF=/etc/mongodb.conf
MONGODB_PORT=27017
CONTROLLER_PORT=6633
RF_HOME=..
export PATH=$PATH:/usr/local/bin:/usr/local/sbin
export PYTHONPATH=$PYTHONPATH:$RF_HOME

cd $RF_HOME

wait_port_listen() {
    port=$1
    while ! `nc -z localhost $port` ; do
        echo -n .
        sleep 1
    done
}

echo_bold() {
    echo -e "\\033[1m${1}\\033[0m"
}

kill_process_tree() {
    top=$1
    pid=$2

    children=`ps -o pid --no-headers --ppid ${pid}`

    for child in $children
    do
        kill_process_tree 0 $child
    done

    if [ $top -eq 0 ]; then
        kill -9 $pid &> /dev/null
    fi
}

reset() {
    init=$1;
    if [ $init -eq 1 ]; then
        echo_bold "-> Starting $SCRIPT_NAME";
    else
        echo_bold "-> Stopping child processes...";
        kill_process_tree 1 $$
    fi

    ovs-vsctl del-br dp0 &> /dev/null;
    ovs-vsctl emer-reset &> /dev/null;

    echo_bold "-> Stopping and resetting LXC VMs...";
    for vm in ''' % (fileName))
        for switch in self.switches:
            fout.write('''"rfvm%s" ''' % switch) 
        fout.write('''
    do
        lxc-shutdown -n "$vm";
        while true
        do
            if lxc-info -q -n "$vm" | grep -q "STOPPED"; then
                break;
            fi
            echo -n .
            sleep 1
        done
    done
    echo_bold "-> Deleting (previous) run data...";
    mongo db --eval "
        db.getCollection('rftable').drop(); 
        db.getCollection('rfconfig').drop(); 
        db.getCollection('rfstats').drop(); 
        db.getCollection('rfclient<->rfserver').drop(); 
        db.getCollection('rfserver<->rfproxy').drop();
    "
''')     
        for switch in self.switches:
            fout.write('''
    rm -rf /var/lib/lxc/rfvm%s/rootfs/opt/rfclient;
''' % switch)
        fout.write('''
}
reset 1
trap "reset 0; exit 0" INT

echo_bold "-> Setting up the management bridge (lxcbr0)..."
ifconfig lxcbr0 192.169.1.1 up

echo_bold "-> Setting up MongoDB..."
sed -i "/bind_ip/c\\bind_ip = 127.0.0.1,192.169.1.1" $MONGODB_CONF
service mongodb restart
wait_port_listen $MONGODB_PORT

echo_bold "-> Configuring the virtual machines..."
# Create the rfclient dir
''')
        for switch in self.switches:
            fout.write('''
mkdir /var/lib/lxc/rfvm%s/rootfs/opt/rfclient
            ''' % switch)
        fout.write('''
# Copy the rfclient executable
            ''')
        for switch in self.switches:
            fout.write('''
cp build/rfclient /var/lib/lxc/rfvm%s/rootfs/opt/rfclient/rfclient
            ''' % switch)
        fout.write('''
# We sleep for a few seconds to wait for the interfaces to go up
            ''')
        for switch in self.switches:
            fout.write('''
echo "#!/bin/sh" > /var/lib/lxc/rfvm%s/rootfs/root/run_rfclient.sh
echo "sleep 3" >> /var/lib/lxc/rfvm%s/rootfs/root/run_rfclient.sh
echo "/etc/init.d/quagga start" >> /var/lib/lxc/rfvm%s/rootfs/root/run_rfclient.sh
echo "/opt/rfclient/rfclient > /var/log/rfclient.log" >> /var/lib/lxc/rfvm%s/rootfs/root/run_rfclient.sh
            ''' % (switch,switch,switch,switch))
        for switch in self.switches:
            fout.write('''
chmod +x /var/lib/lxc/rfvm%s/rootfs/root/run_rfclient.sh
            ''' % (switch))
        fout.write('''
echo_bold "-> Starting the virtual machines..."
            ''')
        for switch in self.switches:
            fout.write('''
lxc-start -n rfvm%s -d
            ''' % (switch))
        fout.write('''
echo_bold "-> Starting the controller and RFPRoxy..."
cd pox
./pox.py log.level --=INFO topology openflow.topology openflow.discovery rfproxy rfstats &
cd -
wait_port_listen $CONTROLLER_PORT

echo_bold "-> Starting RFServer..."
./rfserver/rfserver.py %s/%sconfig.csv &

echo_bold "-> Starting the control plane network (dp0 VS)..."
ovs-vsctl add-br dp0
            '''% (self.rftestName, self.rftestName))
        for switch in self.switches:
            for i in range(self.switch_port[switch]):
                fout.write('''
ovs-vsctl add-port dp0 rfvm%s.%d
            ''' % (switch, i+1))
        fout.write('''
ovs-vsctl set Bridge dp0 other-config:datapath-id=7266767372667673
ovs-vsctl set-controller dp0 tcp:127.0.0.1:$CONTROLLER_PORT

echo_bold "---"
echo_bold "This test is up and running."
echo_bold "Start Mininet:"
echo_bold "  $ sudo mn --custom mininet/custom/topo-4sw-4host.py --topo=rftest2"
echo_bold "    --controller=remote,ip=[host address],port=6633 --pre=ipconf"
echo_bold "Replace [host address] with the address of this host's interface "
echo_bold "connected to the Mininet VM."
echo_bold "Then try pinging everything:"
echo_bold "  mininet> pingall"
echo_bold "You can stop this test by pressing CTRL+C."
echo_bold "---"
wait

exit 0
            ''')
        fout.close()

    def generateConfigDir(self):
        basepath = self.rftestName+"/"+"config"
        switchIndex = 0
        for switch in self.switches:
            switchIndex += 1
            a = switchIndex/81
            b = switchIndex/9+1
            c = switchIndex%9+1
            switchpath = basepath +"/rfvm"+switch
            if not os.path.exists(switchpath):
                os.makedirs(switchpath)
            configfile = switchpath + "/config"
            fout = open(configfile, "w")
            fout.write('''lxc.utsname = rfvm%s
lxc.network.type = veth
lxc.network.flags = up
lxc.network.hwaddr = 02:%d%d:%d0:%d0:%d0:%d0
lxc.network.link=lxcbr0
                ''' % (switch,a,b,c,c,c,c))
            for i in range(self.switch_port[switch]):
                fout.write('''
lxc.network.type = veth
lxc.network.flags = up
lxc.network.veth.pair = rfvm%s.%d
lxc.network.hwaddr = 02:%d%d:%d%d:%d%d:%d%d:%d%d:
                ''' % (switch,i+1,a,b,c,i+1,c,i+1,c,i+1,c,i+1))
            fout.write('''
lxc.devttydir = lxc
lxc.tty = 4
lxc.pts = 1024
lxc.rootfs = /var/lib/lxc/rfvm%s/rootfs
lxc.mount  = /var/lib/lxc/rfvm%s/fstab
lxc.arch = amd64
lxc.cap.drop = sys_module mac_admin
lxc.pivotdir = lxc_putold

# uncomment the next line to run the container unconfined:
#lxc.aa_profile = unconfined

lxc.cgroup.devices.deny = a
# Allow any mknod (but not using the node)
lxc.cgroup.devices.allow = c *:* m
lxc.cgroup.devices.allow = b *:* m
# /dev/null and zero
lxc.cgroup.devices.allow = c 1:3 rwm
lxc.cgroup.devices.allow = c 1:5 rwm
# consoles
lxc.cgroup.devices.allow = c 5:1 rwm
lxc.cgroup.devices.allow = c 5:0 rwm
#lxc.cgroup.devices.allow = c 4:0 rwm
#lxc.cgroup.devices.allow = c 4:1 rwm
# /dev/{,u}random
lxc.cgroup.devices.allow = c 1:9 rwm
lxc.cgroup.devices.allow = c 1:8 rwm
lxc.cgroup.devices.allow = c 136:* rwm
lxc.cgroup.devices.allow = c 5:2 rwm
# rtc
lxc.cgroup.devices.allow = c 254:0 rwm
#fuse
lxc.cgroup.devices.allow = c 10:229 rwm
#tun
lxc.cgroup.devices.allow = c 10:200 rwm
#full
lxc.cgroup.devices.allow = c 1:7 rwm
#hpet
lxc.cgroup.devices.allow = c 10:228 rwm
#kvm
lxc.cgroup.devices.allow = c 10:232 rwm
                ''' % (switch,switch))
            fout.close()
            etcpath = switchpath+"/rootfs/etc"
            if not os.path.exists(etcpath):
                os.makedirs(etcpath)
            fout = open (etcpath+"/sysctl.conf", "w")
            fout.write('''#
# /etc/sysctl.conf - Configuration file for setting system variables
# See /etc/sysctl.d/ for additional system variables
# See sysctl.conf (5) for information.
#

#kernel.domainname = example.com

# Uncomment the following to stop low-level messages on console
#kernel.printk = 3 4 1 3

##############################################################3
# Functions previously found in netbase
#

# Uncomment the next two lines to enable Spoof protection (reverse-path filter)
# Turn on Source Address Verification in all interfaces to
# prevent some spoofing attacks
#net.ipv4.conf.default.rp_filter=1
#net.ipv4.conf.all.rp_filter=1

# Uncomment the next line to enable TCP/IP SYN cookies
# See http://lwn.net/Articles/277146/
# Note: This may impact IPv6 TCP sessions too
#net.ipv4.tcp_syncookies=1

# Uncomment the next line to enable packet forwarding for IPv4
net.ipv4.ip_forward=1

# Uncomment the next line to enable packet forwarding for IPv6
#  Enabling this option disables Stateless Address Autoconfiguration
#  based on Router Advertisements for this host
#net.ipv6.conf.all.forwarding=1


###################################################################
# Additional settings - these settings can improve the network
# security of the host and prevent against some network attacks
# including spoofing attacks and man in the middle attacks through
# redirection. Some network environments, however, require that these
# settings are disabled so review and enable them as needed.
#
# Do not accept ICMP redirects (prevent MITM attacks)
#net.ipv4.conf.all.accept_redirects = 0
#net.ipv6.conf.all.accept_redirects = 0
# _or_
# Accept ICMP redirects only for gateways listed in our default
# gateway list (enabled by default)
# net.ipv4.conf.all.secure_redirects = 1
#
# Do not send ICMP redirects (we are not a router)
#net.ipv4.conf.all.send_redirects = 0
#
# Do not accept IP source route packets (we are not a router)
#net.ipv4.conf.all.accept_source_route = 0
#net.ipv6.conf.all.accept_source_route = 0
#
# Log Martian Packets
#net.ipv4.conf.all.log_martians = 1
#
                ''')
            fout.close()
            fout = open (etcpath+"/rc.local", "w")
            fout.write('''#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.

/root/run_rfclient.sh &

exit 0

                ''')
            fout.close()
            networkpath = etcpath+"/network"
            if not os.path.exists(networkpath):
                os.makedirs(networkpath)
            fout = open (networkpath+"/interfaces", "w")
            fout.write('''auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address 192.169.1.%d
    netmask 255.255.255.0
    network 192.169.1.0
    broadcast 192.169.1.255
                ''' % (switchIndex+5))
            fout.close()
            quaggapath = etcpath+"/quagga"
            if not os.path.exists(quaggapath):
                os.makedirs(quaggapath)
            fout = open (quaggapath+"/debian.conf", "w")
            fout.write('''#
# If this option is set the /etc/init.d/quagga script automatically loads
# the config via "vtysh -b" when the servers are started. 
# Check /etc/pam.d/quagga if you intend to use "vtysh"!
#
vtysh_enable=yes
zebra_options=" --daemon -A 127.0.0.1"
bgpd_options="  --daemon -A 127.0.0.1"
ospfd_options=" --daemon -A 127.0.0.1"
ospf6d_options="--daemon -A ::1"
ripd_options="  --daemon -A 127.0.0.1"
ripngd_options="--daemon -A ::1"
isisd_options=" --daemon -A 127.0.0.1"

                ''')
            fout.close()
            fout = open (quaggapath+"/daemons", "w")
            fout.write('''# This file tells the quagga package which daemons to start.
#
# Entries are in the format: <daemon>=(yes|no|priority)
#   0, "no"  = disabled
#   1, "yes" = highest priority
#   2 .. 10  = lower priorities
# Read /usr/share/doc/quagga/README.Debian for details.
#
# Sample configurations for these daemons can be found in
# /usr/share/doc/quagga/examples/.
#
# ATTENTION: 
#
# When activation a daemon at the first time, a config file, even if it is
# empty, has to be present *and* be owned by the user and group "quagga", else
# the daemon will not be started by /etc/init.d/quagga. The permissions should
# be u=rw,g=r,o=.
# When using "vtysh" such a config file is also needed. It should be owned by
# group "quaggavty" and set to ug=rw,o= though. Check /etc/pam.d/quagga, too.
#
zebra=yes
bgpd=no
ospfd=yes
ospf6d=no
ripd=no
ripngd=no
isisd=no
                ''')
            fout.close()
            fout = open (quaggapath+"/zebra.conf", "w")
            fout.write('''password routeflow
enable password routeflow
!
log file /var/log/quagga/zebra.log
password 123
enable password 123
!
''')        
            for i in range(self.switch_port[switch]):
                if self.switch_port_address[switch][i].startswith("172.31"):
                    fout.write('''
interface eth%d
        ip address %s1/24
!
''' %(i+1, self.switch_port_address[switch][i]))
                else:
                    fout.write('''
interface eth%d
        ip address %s%d/24
!
''' %(i+1, self.switch_port_address[switch][i], switchIndex))
            fout.close()
            fout = open (quaggapath + "/ospfd.conf", "w")
            fout.write('''password routeflow
enable password routeflow
!
router ospf
    network 172.16.0.0/12 area 0
                ''')
            for i in range(len(self.connections)-len(self.hosts)):
                subnet = str(i+1)+".0.0.0/8"
                fout.write('''  network %s area 0
                    ''' % subnet)
            fout.write('''!
log file /var/log/quagga/ospfd.log
!
                ''')
            for i in range(self.switch_port[switch]+5):
                fout.write('''interface eth%d
    ip ospf hello-interval 1
    ip ospf dead-interval 4
!
                    ''' % i)
            fout.close()

    def generateCSV(self):
        fileName = self.rftestName+"config.csv"
        fout = open(self.rftestName+"/"+fileName, "w")
        fout.write('''vm_id,vm_port,ct_id,dp_id,dp_port
''')    
        switchIndex = 0
        for switch in self.switches:
            switchIndex += 1
            a = switchIndex/81
            b = switchIndex/9+1
            c = switchIndex%9+1
            vm_id = "02"+str(a)+str(b)+str(c)+"0"+str(c)+"0"+str(c)+"0"+str(c)+"0"
            switch_id = int(switch[1:])
            switch_id = format(switch_id,"x")
            for i in range(self.switch_port[switch]):
                line = vm_id + ","+ str(i+1)+",0,"+switch_id+","+str(i+1)+"\n"
                fout.write(line)
        fout.close()

    def generateCreateFile(self):
        fileName = "create"
        fout = open(self.rftestName+"/"+fileName, "w")
        fout.write('''#!/bin/bash

if [ "$EUID" != "0" ]; then
  echo "You must be root to run this script. Sorry, dude!"
  exit 1
fi

LXCDIR="/var/lib/lxc"
CONFIG="config"

# Setup LXC and base container
#apt-get -y --force-yes install lxc
mkdir -p $LXCDIR
lxc-create -t ubuntu -n base

#chroot $LXCDIR/base/rootfs apt-get update
# !!!
# ADD THE PACKETS YOU NEED TO INSTALL HERE
# !!!
#chroot $LXCDIR/base/rootfs apt-get -y --force-yes install quagga libboost-thread-dev libboost-system-dev libboost-filesystem-dev libboost-program-options-dev rsyslog vlan tcpdump
# !!!

# Clone the base container to make other containers based on config
cd $CONFIG
for VM in *
do
    if [ -d $LXCDIR/$VM ]
    then
        echo "vm exist";
    else
        lxc-clone -o base -n $VM
    fi 
    #rm -rf $LXCDIR/$VM
    cp -R $VM/* $LXCDIR/$VM
done
''')
        fout.close()

if __name__=='__main__':
    if len(sys.argv) != 3:
        print "sudo python autorf.py rftestname confName"
        sys.exit(1)
    net = Topology(sys.argv[1], sys.argv[2])
    net.generateMNTopoFile()
    net.generateIpconfFile()
    net.generateRftestFile()
    net.generateConfigDir()
    net.generateCSV()
    net.generateCreateFile()
    sys.exit(0)

