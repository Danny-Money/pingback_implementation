# Pingback Implementation
Testing a variation of pingback base on the malware described by [TrustWave](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/backdoor-at-the-end-of-the-icmp-tunnel/)/[SpiderLabs](https://github.com/SpiderLabs/pingback)

pingback_server.py under is ran on the computer that is hosting whatever files you want to download.

pingback_server_v2.py is not complete yet, but has some updated features (getting system info, running terminal commands, planning on automatic retry). It does not work with the v1 client, and the v2 client has not yet been uploaded to GitHub.

pingback_client.py is the v1 client script, is simply asks for the filename & IP address of the server.

# Requirements:
Python 3 (preferably the latest version - 3.12 currently)
Scapy


# Bugs:
For some reason, scapy bugs out on Windows, and does not sniff any packets unless given a specific interface - this problem does not exist on linux.

Scapy will occasionally drop packets for some reason during large transfers that use multiple packets. There is a set delay in currently, but I plan on adding automatic re-transmission for the v2 client/server scripts.

Not really a bug, per-se, but the client & server must be on the same subnet, or else the connection cannot be made.
