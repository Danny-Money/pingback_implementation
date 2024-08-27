from scapy.all import *
from time import sleep

for i in range(0,1):

    print("Enter the file name to download:")

    file = str(input())

    print("Enter the destination IP address:")

    dest_IP = str(input())

    layer3 = IP(dst=dest_IP)
    layer4 = ICMP(type=8)

    data = "downloadë" + file

    packet = layer3/layer4/data

    print('')
    print(packet)
    send(packet)

    print('Waiting for sniff')
    pkts = sniff(filter="icmp and host " + dest_IP, count=2, timeout=10)

    for packet in pkts:
        print(packet)
        print(packet[ICMP].type)
        print(packet[IP].src)
        print(packet[Raw].load)

        payload = str(packet[Raw].load).replace('\\\\','\\')[2:-1].split("\\xc3\\xab")
        print(payload)

        if(len(payload) < 2):
            print("Payload incomplete")
        else:
            if(payload[0] == '0'):
                print("File in single packet, outputting")
                with open(file, "w") as file:
                    file.write(payload[1])
                    file.close()
            elif(payload[0] == '1'):
                print("payload in multiple packets - capturing " + payload[1] + " packets.")
                file_data = b''
                for i in range(0,int(payload[1])):
                    sleep(1)
                    send(IP(dst=dest_IP)/ICMP(type=8))
                    new_pkts = sniff(filter="icmp and host " + dest_IP, count=2, timeout=10)

                    file_data += new_pkts[len(new_pkts) - 1][Raw].load

                    i += 1
                
                with open(file, "wb") as file:
                        file.write(file_data)
                        file.close()

    i += 1