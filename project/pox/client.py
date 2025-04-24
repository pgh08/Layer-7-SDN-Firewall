# from scapy.all import *
# import time

# def packetSending():
#     pkt = IP(dst="10.0.0.1", src='192.168.1.2')/TCP(dport=12345, flags='S')/Raw(load="Hello, server!")
#     send(pkt)

# def handlePacketIn(pkt):
#     tcp_flags = pkt[TCP].flags
#     print(tcp_flags)
#     if pkt.haslayer(RAW):
#         print("Received:", packet[Raw].load.decode('utf-8'))
        
# count = 0
# while count < 100:
# 	packetSending()
# 	time.sleep(5)
# 	count += 1

from socket import *

serverName = "10.0.0.5"
serverPort = 12000

clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName,serverPort))

while True:
    sentence = input("Reply : ")
    clientSocket.send(sentence.encode())
    msg = clientSocket.recv(1024).decode()
    print ('From Server:', msg)
    
clientSocket.close()