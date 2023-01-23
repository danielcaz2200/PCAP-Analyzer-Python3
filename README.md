# Wireshark Packet Capture Analyzer in Python3
## This script is intended to be able to study Wireshark packet capture files both in a command line format and via Google maps

### How to use this program:
Requires Python3 and the installation of the dpkt, pygeoip, requests and pyshark libs

Installation links:

https://dpkt.readthedocs.io/en/latest/installation.html

https://pypi.org/project/pygeoip/

https://pypi.org/project/requests

https://pypi.org/project/pyshark/

## Once libraries are installed to your installation of Python3...

You will need to open the current directory that contains main.py and run the script, ex: `python3 main.py`

Once done, the current working directory will contain the /mapdata and /pcap_files directories

## Documentation
## The follow commandline arguments are applicable to main.py

`--summarize` produces a pagable summary of the current packet being inspected with IP and transport layer information

`--count` counts the amount of packets recorded in each .pcap file located in `/pcap_files`

`--kml` produces a **Keyhole Markup Language** file from the packet captures found in `/pcap_files` which can be directly imported to Google maps to analyze network traffic

## Importing .pcap files to /pcap_files

Wireshark captures may be saved as .pcap files by clicking on File and saving the current capture as a .pcap file as seen below

![pcap](https://user-images.githubusercontent.com/60197297/213968734-a3697ce5-eedb-47db-9e6b-3fc9bc292e96.jpg)

## Importing .kml files to Google Maps

### Information regarding importing .kml files for visualization can be found at Google's own documentation:

https://support.google.com/mymaps/answer/3024836?hl=en&co=GENIE.Platform%3DDesktop#zippy=%2Cstep-import-info-into-the-map
