AutoRFConf
==========

Automation scripts for [RouteFlow](https://github.com/CPqD/RouteFlow) Configuration.

What you need to do is just to edit .conf file for the network topology. This script will generate *topo.py* *ipconf* *config.csv* *rftest* *create* and *rfvm config files* for you.

---

## How to use: sudo python autorf.py rftestName rftopology.conf


A sample of .conf file:
`host
h1,h2
switch
s3,s4,s5,s6
connection
h1 s3
h2 s6
s3 s4
s4 s6
s3 s5
s5 s6`

And what you should be careful about are:
- host names should be started with "h", and followed by a number, like h3, h45
- switch names should be started with "s", and followed by a number, like s4, s13
- the number of switches should be less than 240 (It seems that mac address should be started by "02"). Refer to _generateConfigDir_ method for detailed information.
- rftestName should be started with letters or "\_", for this variable is also used for the Topo class.
