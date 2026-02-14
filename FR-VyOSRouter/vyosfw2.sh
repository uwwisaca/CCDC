set firewall ipv4 forward filter rule 1 action accept
set firewall ipv4 forward filter rule 1 state established enable
set firewall ipv4 forward filter rule 1 state related enable
set firewall ipv4 forward filter rule 1 description "allow established/related"
set firewall ipv4 forward filter rule 100 log 
set firewall ipv4 forward filter rule 100 action drop
set firewall ipv4 forward filter rule 100 protocol tcp
set firewall ipv4 forward filter rule 100 destination port 22
set firewall ipv4 forward filter rule 100 description "DROP forwarded port tcp/22"
set firewall ipv6 forward filter rule 101 log
set firewall ipv6 forward filter rule 101 action drop
set firewall ipv6 forward filter rule 101 protocol tcp
set firewall ipv6 forward filter rule 101 destination port 22
set firewall ipv6 forward filter rule 101 description "DROP forwarded port tcp/22"
set firewall ipv4 forward filter rule 110 log 
set firewall ipv4 forward filter rule 110 action drop
set firewall ipv4 forward filter rule 110 protocol tcp
set firewall ipv4 forward filter rule 110 destination port 23
set firewall ipv4 forward filter rule 110 description "DROP forwarded port tcp/23"
set firewall ipv6 forward filter rule 111 log
set firewall ipv6 forward filter rule 111 action drop
set firewall ipv6 forward filter rule 111 protocol tcp
set firewall ipv6 forward filter rule 111 destination port 23
set firewall ipv6 forward filter rule 111 description "DROP forwarded port tcp/23"
set firewall ipv4 forward filter rule 120 log 
set firewall ipv4 forward filter rule 120 action drop
set firewall ipv4 forward filter rule 120 protocol tcp
set firewall ipv4 forward filter rule 120 destination port 3389
set firewall ipv4 forward filter rule 120 description "DROP forwarded port tcp/3389"
set firewall ipv6 forward filter rule 121 log
set firewall ipv6 forward filter rule 121 action drop
set firewall ipv6 forward filter rule 121 protocol tcp
set firewall ipv6 forward filter rule 121 destination port 3389
set firewall ipv6 forward filter rule 121 description "DROP forwarded port tcp/3389"
set firewall ipv4 forward filter rule 130 log 
set firewall ipv4 forward filter rule 130 action drop
set firewall ipv4 forward filter rule 130 protocol tcp
set firewall ipv4 forward filter rule 130 destination port 445
set firewall ipv4 forward filter rule 130 description "DROP forwarded port tcp/445"
set firewall ipv6 forward filter rule 131 log
set firewall ipv6 forward filter rule 131 action drop
set firewall ipv6 forward filter rule 131 protocol tcp
set firewall ipv6 forward filter rule 131 destination port 445
set firewall ipv6 forward filter rule 131 description "DROP forwarded port tcp/445"
set firewall ipv4 forward filter rule 132 log 
set firewall ipv4 forward filter rule 132 action drop
set firewall ipv4 forward filter rule 132 protocol tcp
set firewall ipv4 forward filter rule 132 destination port 139
set firewall ipv4 forward filter rule 132 description "DROP forwarded port tcp/139"
set firewall ipv6 forward filter rule 133 log
set firewall ipv6 forward filter rule 133 action drop
set firewall ipv6 forward filter rule 133 protocol tcp
set firewall ipv6 forward filter rule 133 destination port 139
set firewall ipv6 forward filter rule 133 description "DROP forwarded port tcp/139"
set firewall ipv4 forward filter rule 134 log 
set firewall ipv4 forward filter rule 134 action drop
set firewall ipv4 forward filter rule 134 protocol tcp
set firewall ipv4 forward filter rule 134 destination port 135
set firewall ipv4 forward filter rule 134 description "DROP forwarded port tcp/135"
set firewall ipv6 forward filter rule 135 log
set firewall ipv6 forward filter rule 135 action drop
set firewall ipv6 forward filter rule 135 protocol tcp
set firewall ipv6 forward filter rule 135 destination port 135
set firewall ipv6 forward filter rule 135 description "DROP forwarded port tcp/135"
set firewall ipv4 forward filter rule 140 log 
set firewall ipv4 forward filter rule 140 action drop
set firewall ipv4 forward filter rule 140 protocol tcp
set firewall ipv4 forward filter rule 140 destination port 5985
set firewall ipv4 forward filter rule 140 description "DROP forwarded port tcp/5985"
set firewall ipv6 forward filter rule 141 log
set firewall ipv6 forward filter rule 141 action drop
set firewall ipv6 forward filter rule 141 protocol tcp
set firewall ipv6 forward filter rule 141 destination port 5985
set firewall ipv6 forward filter rule 141 description "DROP forwarded port tcp/5985"
set firewall ipv4 forward filter rule 142 log 
set firewall ipv4 forward filter rule 142 action drop
set firewall ipv4 forward filter rule 142 protocol tcp
set firewall ipv4 forward filter rule 142 destination port 5986
set firewall ipv4 forward filter rule 142 description "DROP forwarded port tcp/5986"
set firewall ipv6 forward filter rule 143 log
set firewall ipv6 forward filter rule 143 action drop
set firewall ipv6 forward filter rule 143 protocol tcp
set firewall ipv6 forward filter rule 143 destination port 5986
set firewall ipv6 forward filter rule 143 description "DROP forwarded port tcp/5986"
set firewall ipv4 forward filter rule 150 log 
set firewall ipv4 forward filter rule 150 action drop
set firewall ipv4 forward filter rule 150 protocol tcp
set firewall ipv4 forward filter rule 150 destination port 631
set firewall ipv4 forward filter rule 150 description "DROP forwarded port tcp/631"
set firewall ipv6 forward filter rule 151 log
set firewall ipv6 forward filter rule 151 action drop
set firewall ipv6 forward filter rule 151 protocol tcp
set firewall ipv6 forward filter rule 151 destination port 631
set firewall ipv6 forward filter rule 151 description "DROP forwarded port tcp/631"
set firewall ipv4 forward filter rule 152 log 
set firewall ipv4 forward filter rule 152 action drop
set firewall ipv4 forward filter rule 152 protocol udp
set firewall ipv4 forward filter rule 152 destination port 631
set firewall ipv4 forward filter rule 152 description "DROP forwarded port udp/631"
set firewall ipv6 forward filter rule 153 log
set firewall ipv6 forward filter rule 153 action drop
set firewall ipv6 forward filter rule 153 protocol udp
set firewall ipv6 forward filter rule 153 destination port 631
set firewall ipv6 forward filter rule 153 description "DROP forwarded port udp/631"
set firewall ipv4 forward filter rule 500 action accept
set firewall ipv4 forward filter rule 500 inbound-interface eth1
set firewall ipv4 forward filter rule 500 outbound-interface eth0
set firewall ipv4 forward filter rule 500 description "allow eth1 -> eth0 outbound"
set firewall ipv4 forward filter rule 501 action accept
set firewall ipv4 forward filter rule 501 inbound-interface eth2
set firewall ipv4 forward filter rule 501 outbound-interface eth0
set firewall ipv4 forward filter rule 501 description "allow eth2 -> eth0 outbound"
set firewall ipv4 forward filter rule 1010 action accept
set firewall ipv4 forward filter rule 1010 destination address 172.25.36.155
set firewall ipv4 forward filter rule 1010 protocol tcp
set firewall ipv4 forward filter rule 1010 destination port 53
set firewall ipv4 forward filter rule 1010 description "ALLOW AD TCP 53"
set firewall ipv4 forward filter rule 1011 action accept
set firewall ipv4 forward filter rule 1011 destination address 172.25.36.155
set firewall ipv4 forward filter rule 1011 protocol udp
set firewall ipv4 forward filter rule 1011 destination port 53
set firewall ipv4 forward filter rule 1011 description "ALLOW AD UDP 53"
set firewall ipv4 forward filter rule 1019 action drop
set firewall ipv4 forward filter rule 1019 destination address 172.25.36.155
set firewall ipv4 forward filter rule 1019 description "DROP all other traffic to AD Public"
set firewall ipv4 forward filter rule 1020 action accept
set firewall ipv4 forward filter rule 1020 destination address 172.25.36.140
set firewall ipv4 forward filter rule 1020 protocol tcp
set firewall ipv4 forward filter rule 1020 destination port 80
set firewall ipv4 forward filter rule 1020 description "ALLOW WinWeb TCP 80"
set firewall ipv4 forward filter rule 1029 action drop
set firewall ipv4 forward filter rule 1029 destination address 172.25.36.155
set firewall ipv4 forward filter rule 1029 description "DROP all other traffic to WinWeb"
set firewall ipv4 forward filter rule 1030 action accept
set firewall ipv4 forward filter rule 1030 destination address 172.25.36.162
set firewall ipv4 forward filter rule 1030 protocol tcp
set firewall ipv4 forward filter rule 1030 destination port 21
set firewall ipv4 forward filter rule 1030 description "ALLOW FTP TCP 21 to 172.25.36.155"
set firewall ipv4 forward filter rule 1031 action accept
set firewall ipv4 forward filter rule 1031 destination address 172.25.36.162
set firewall ipv4 forward filter rule 1031 protocol tcp
set firewall ipv4 forward filter rule 1031 destination port 20
set firewall ipv4 forward filter rule 1031 description "ALLOW FTP TCP 20 to 172.25.36.155"
set firewall ipv4 forward filter rule 1039 action drop
set firewall ipv4 forward filter rule 1039 destination address 172.25.36.162
set firewall ipv4 forward filter rule 1039 description "DROP all other traffic to 172.25.36.155"
set firewall ipv4 forward filter rule 1049 action drop
set firewall ipv4 forward filter rule 1049 destination address 172.25.36.144
set firewall ipv4 forward filter rule 1049 description "DROP all other traffic to 172.25.36.155"
set firewall ipv4 forward filter rule 1050 action accept
set firewall ipv4 forward filter rule 1050 destination address 172.25.36.9
set firewall ipv4 forward filter rule 1050 protocol tcp
set firewall ipv4 forward filter rule 1050 destination port 80
set firewall ipv4 forward filter rule 1050 description "ALLOW Splunk TCP 80"
set firewall ipv4 forward filter rule 1059 action drop
set firewall ipv4 forward filter rule 1059 destination address 172.25.36.9
set firewall ipv4 forward filter rule 1059 description "DROP all other traffic to Splunk Public"
set firewall ipv4 forward filter rule 1060 action accept
set firewall ipv4 forward filter rule 1060 destination address 172.25.36.11
set firewall ipv4 forward filter rule 1060 protocol tcp
set firewall ipv4 forward filter rule 1060 destination port 80
set firewall ipv4 forward filter rule 1060 description "ALLOW Ecom TCP 80"
set firewall ipv4 forward filter rule 1069 action drop
set firewall ipv4 forward filter rule 1069 destination address 172.25.36.11
set firewall ipv4 forward filter rule 1069 description "DROP all other traffic to Ecom Public"
set firewall ipv4 forward filter rule 1070 action accept
set firewall ipv4 forward filter rule 1070 destination address 172.25.36.39
set firewall ipv4 forward filter rule 1070 protocol tcp
set firewall ipv4 forward filter rule 1070 destination port 25
set firewall ipv4 forward filter rule 1070 description "ALLOW Fedora TCP 25"
set firewall ipv4 forward filter rule 1071 action accept
set firewall ipv4 forward filter rule 1071 destination address 172.25.36.39
set firewall ipv4 forward filter rule 1071 protocol tcp
set firewall ipv4 forward filter rule 1071 destination port 587
set firewall ipv4 forward filter rule 1071 description "ALLOW Fedora TCP 587"
set firewall ipv4 forward filter rule 1072 action accept
set firewall ipv4 forward filter rule 1072 destination address 172.25.36.39
set firewall ipv4 forward filter rule 1072 protocol tcp
set firewall ipv4 forward filter rule 1072 destination port 110
set firewall ipv4 forward filter rule 1072 description "ALLOW Fedora TCP 110"
set firewall ipv4 forward filter rule 1079 action drop
set firewall ipv4 forward filter rule 1079 destination address 172.25.36.39
set firewall ipv4 forward filter rule 1079 description "DROP all other traffic to Fedora Public"
set service suricata address-group home-net address "172.20.242.0/24"
set service suricata address-group home-net address "172.20.240.0/24"
set service suricata address-group home-net address "172.16.101.0/24"
set service suricata address-group home-net address "172.20.102.0/24"
set service suricata address-group external-net group "!home-net"
set service suricata port-group http-ports port "80"
set service suricata port-group ssh-ports port "22"
set service suricata interface eth0
set service suricata interface eth1
set service suricata interface eth2
