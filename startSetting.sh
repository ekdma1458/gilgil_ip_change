iptables -F
iptables -t mangle -F

iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0  
iptables -t mangle -A PREROUTING -p tcp --sport 443 -j NFQUEUE --queue-num 0
