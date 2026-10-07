from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, wrpcap

cliente = "10.0.0.5"
pacotes = [
       IP(src=cliente, dst="10.0.0.1") / UDP(sport=51000, dport=53)
       / DNS(rd=1, qd=DNSQR(qname="example.com")),
       IP(src=cliente, dst="10.0.0.1") / UDP(sport=51001, dport=53)
       / DNS(rd=1, qd=DNSQR(qname="xk3j9q2z7v1w8.example.net")),
       IP(src=cliente, dst="203.0.113.50") / TCP(sport=52000, dport=80, flags="PA")
       / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
   ]
wrpcap("samples/demo.pcap", pacotes)
print("Criado samples/demo.pcap com", len(pacotes), "pacotes")