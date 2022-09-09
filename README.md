# rledbat_module

rLEDBAT prototype (https://datatracker.ietf.org/doc/html/draft-irtf-iccrg-rledbat-02)

rLEDBAT flows are identified by the remote TCP port.
The current code manages a single flow per node.  
To clean the state of an rLEDBAT execution (i.e., the minimum RTT observed), reinstall the module (execute ./install_rledbat.sh). rLEDBAT writes traces to system logs. 

install_rledbat.sh: Compiles and installs the rLEDBAT modules

rledbat_receive.c: Code implementing hook parsing incoming packets

kernel/xt_TWIN.c: Code implementing hook parsing and modifying outgoing packets

## credits

rledbat_receive.c is derived from Module for printing TCP packet data', Sam Protsenko, https://stackoverflow.com/questions/29553990/print-tcp-packet-data
xt_TWIN.c module is derived from TCP window modification target for IP tables, https://github.com/p5n/ipt_tcpwin, by Sergej Pupykin <sergej@p5n.pp.ru> and  Vadim Fedorenko <junjunk@fromru.com>
