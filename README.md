# TCP Analysis

This program is an implementation of TCPDump, a command-line tool that analyzes the packets captured on the wire (packets from computer and to the computer).  PCAP is the file format used to store packets captured on the file.  These files are in binary format and not easily readable.  This program will parse the PCAP file with the help of a PCAP library in order to extract desired packet information.  This program is specifically designed to analyze a PCAP file for the TCP flows in the trace file.  A TCP flow starts with a TCP "SYN" and ends at a TCP "FIN" between two hosts with fixed IP address and ports.  There can be multiple TCP flows at the same time between the two hosts on different ports.   The program uses a PCAP library to convert a PCAP packet from binary to byte format in order to extract information from the bytes.

Included is a sample pcap file where packets between 130.245.145.12 and 128.208.2.198 have been captured.  Node 130.245.145.12 establishes the connection with 128.208.2.198 and then sends data. The trace was captured at the sender.

# API used

The analysis_pcap_tcp.py is written in Python3 and it imports the following external libraries: dpkt, time, and sys.  The dpkt library is from the dpkt API.  This API was used to help read and parse the information in the given PCAP file. The time library is used to calculate the amount of packets sent between sender and receiver in a given amount of time and compare this time to RTT.  Finally, the sys library is used so the program can be run in the command line.

# How to run

To run the analysis_pcap_tcp.py file, open the command prompt.  On the command line, type 'python' followed by a space and then the path name of the directory.
Example: <br />
python analysis_pcap_tcp.py <br />
You will be prompted with the prompt: "Please input pcap file" <br />
Type in the directory path of the pcap file. <br />
Example: pcapfile.pcap
