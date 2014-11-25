Group details:
Rahul Mahadev - 1PI12IS078
Sathvik Varanashi - 1PI12IS097

Program execution:
run as:
python asn2.7.py -f new.pcap

###################PACKET-1#####################
Destination MAC : 00:26:15:66:60:5f Source MAC : 94:db:c9:49:8a:a1
IPv 4
Source Address: 192.168.1.4 Destination Address 27.3.254.54                                                                                                                                     
UDP Packet                                                                                                                                                                                      
Source Port : 7881 Dest Port : 63413 Length : 57 Given Checksum : 42429                                                                                                                         
Data is: d1:rd2:id20:���N�Y5�'�h������&e1:t4:XU1:y1:re                                                                                                                                          
Calculated Checksum is  42429
Valid Checksum

Parts of the Program:

User defined functions:
	getPacketStream: function to get a string from the file
	getPackets:Splits the given packet stream into multiple packets considering length of the packetand headers
	csummer: does 16-bit one's complement(utility function)
	address: mac address in human readable format
	analyzePacket: most important function of the program which identifies the various portion of a packet and calculates and validates the checksum,port and address information are discovered here.
Library functions:
	Struct unpack:unpacks binary data into the specified format in the format specified
	socket inet_ntoa :converts numeric data to address string

FLOW of the program:
	main->getPacketstream,getPackets,analyzePacket->address,csummer

Dificulties faced: 
* Lack of documentaion on libpcap format led to a lot of trial and error to determine the blocks and headers.
* Splitting a stream of packets
*Calulation of the checksum 