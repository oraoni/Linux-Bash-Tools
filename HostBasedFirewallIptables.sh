INTERFACE="eth0"
IPADDR="192.168.0.2"
BCASTADDR="192.168.0.255"

TCP_IN="ssh http ftp"
TCP_OUT="domain ssh http https 1024:65535"
UDP_IN=""
UDP_OUT="domain ntp"
ICMP_IN="destination-unreachable source-quench echo-request time-exceeded parameter-problem"
ICMP_OUT="destination-unreachable source-quench echo-request time-exceeded parameter-problem"

FW="/sbin/iptables"
NEW="${FW} --append"
MODPROBE="/sbin/modprobe"

$MODPROBE ip_conntrack_ftp

$FW --flush
$FW --delete-chain

for ch in INPUT OUTPUT FORWARD; do
 $FW -P $ch DROP
done

$FW -N discard # create new rule
$NEW discard -p udp -d ${BCASTADDR} -j DROP
$NEW discard -p udp -d 255.255.255.255 -j DROP
$NEW discard -m limit --limit 10/minute --limit-burst 20 -j LOG
$NEW discard -p tcp --syn -d ${IPADDR} --dport ident -j REJECT --reject-with tcp-reset
$NEW discard -j DROP

$NEW INPUT -i '!' ${INTERFACE} -j ACCEPT
$NEW INPUT -s 127.0.0.0/8 -j ACCEPT
$NEW OUTPUT -o '!' ${INTERFACE} -j ACCEPT

$NEW INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$NEW OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

for port in ${TCP_IN}; do
    case "${port}" in
    ftp) $NEW INPUT -p tcp --dport ${port} --syn -m state --state NEW -j ACCEPT
       ;;
    *)  $NEW INPUT -p tcp --dport ${port} -j ACCEPT
       $NEW OUTPUT -p tcp ! --syn --sport ${port} -j ACCEPT
       ;;
    esac
done
for port in ${UDP_IN}; do
    $NEW INPUT -p udp --dport ${port} -j ACCEPT
    $NEW OUTPUT -p udp --sport ${port} -j ACCEPT
done
for port in ${TCP_OUT}; do
    $NEW OUTPUT -p tcp --dport ${port} --syn -m state --state NEW -j ACCEPT
done

for port in ${UDP_OUT}; do
    $NEW OUTPUT -p udp --dport ${port} -m state --state NEW -j ACCEPT
done
for t in ${ICMP_IN}; do
    case "${t}" in
    echo-request)
      $NEW INPUT -p icmp --icmp-type echo-request -j ACCEPT
      $NEW OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
      ;;
    *)
      $NEW INPUT -p icmp --icmp-type ${t} -j ACCEPT
      ;;
    esac
done
for t in ${ICMP_OUT}; do
    case "${t}" in
    echo-request)
        $NEW OUTPUT -p icmp --icmp-type ${t} -m state --state NEW -j ACCEPT
        ;;
    *)
        $NEW OUTPUT -p icmp --icmp-type ${t} -j ACCEPT
        ;;
    esac
done

$NEW INPUT -j discard

$NEW OUTPUT -m limit --limit 10/minute --limit-burst 20 -j LOG
$NEW OUTPUT -p tcp -j REJECT --reject-with tcp-reset
$NEW OUTPUT -j REJECT
