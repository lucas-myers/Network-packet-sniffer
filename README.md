1. Things you will need
python --version or python3 --version
pip install scapy or sudo apt install python3-scapy
| needs Administrator/root privileges | sudo/root

Operating System:
I used Ubuntu Linux 

2.Find your interface
ip link or ifconfig

I used ip link and mine was ens33

to exit the scapy shell:
exit()

windows interface is different in powershell and will likely need something like:
\\Device\\NPF_{FFB55D66-BE32-45B1-8A0A-BD39A713E198}
this can be found in wireshark if you hover over connection you use.


3.Capturing packets
Linux:
sudo python3 capture.py -i ens33 or sudo python3 capture.py -i ens33 -f "tcp
python capture.py -i "\\Device\\NPF_{YOUR_INTERFACE_ID}"
or  python capture.py -i "\\Device\\NPF_{YOUR_INTERFACE_ID}" --filter "tcp port 80"

TO STOP CAPTURE: CTRL C

4.Examples

ping traffic:
ping google.com
ICMP Echo Request
ICMP Echo Reply

HTTP traffic:
curl http://example.com
port 80

DNS traffic:
nslookup google.com
port 53

apply filters:
sudo python3 capture.py -i ens33 --filter "udp port 53"
sudo python3 capture.py -i ens33 --filter "tcp"
sudo python3 capture.py -i ens33 --filter "icmp"
