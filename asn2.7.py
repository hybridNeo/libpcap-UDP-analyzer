from struct import *
import socket
import sys
"""
@Author - Rahul Mahadev, Sathvik Varanashi
@Instruction - python asn2.7.py filename.extension
"""


"""
@param string filename The name of the file
@return string the packetstream 
"""
def getPacketStream(filename):
	f = None
	try:
		f = open(filename,'rb')
	except:#incase file does not exist
		print "Enter a valid file"
		exit(0)
	a = f.read()
	f.close()
	return a

"""
@param string packetstream
@return list packets
Splits the given packet stream into multiple packets considering length of the packet
and headers 
"""
def getPackets(packetstream):
	pac = [] #list to hold the packets
	GLOBAL_BOUNDARY =24 #0-24 is the global header
	pointer = 24 #inital pointer which skips over the global header
	length = len(packetstream)
	# print "Total Length is",length
	while(pointer < length): 
	 	l = unpack('I',packetstream[pointer+8:pointer+12])[0] #unpacking the hex length to integer format
	 	packet = packetstream[pointer:(pointer+16)+l] #Extracting the packet
	 	pac.append(packet)
	 	pointer += (l+16) #incrementing the pointer to the start of next packet
	return pac

"""
@param hexint csum
@return int computed checksum
We add the various bits of the packet to obtain a sum which we convert to a 16bit
string and find its 1's complement
"""
def csummer(csum):
	s = str(csum).replace('0x','') 
	while(len(s)>4):
		a = s[len(s)-4:]
		b =s[0:len(s)-4]
		c = int('0x'+str(a),16)+int('0x'+str(b),16)
		s = str(hex(c)).replace('0x','') 
	bina = bin(int('0x'+str(s),16)).replace('0b','')
	bina = bina.zfill(16)
	newbin = ''
	for i in bina:#1's complement calculation
		if(i=='0'):
			newbin+='1'
		else:
			newbin+='0'
	ans = int('0b'+str(newbin),2)
	return ans

"""
@param int address
@return string address
converts integer address to human-understandable address format
"""
def address(a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

"""
@param packet
Main function which analyzes the packet and finds the various addresses and computes checksum
"""
def analyzePacket(packet):
	c_sum = 0 #initializing computed checksum
	header,data = packet[0:16],packet[16:] #Given a packet,got to split its packet header and packet data
	eth_length = 14 #0-14 is the Starting portion of the data reserved for mac addresses and other protocol info
	print 'Destination MAC : ' + address(data[0:6]) + ' Source MAC : ' + address(data[6:12]) 
	IP_LIMIT = 34 #ip header content till 34 byte
	ip_header = data[14:IP_LIMIT] #raw ip header
	iph = unpack('!BBHHHBBH4s4s' , ip_header) #unpacking format for ipheader 
	block = unpack('!HHHH',data[26:34]) #unpacks data pertaining to source and dest address
	c_sum += reduce(lambda x,y:x+y,block)
	version_ihl = iph[0] 
	version = version_ihl >> 4
	print 'IPv',version #IP version
	ihl = version_ihl & 0xF 
	iph_length = ihl * 4 #length of ip header
	protocol = iph[6] #TCP,UDP etc
	c_sum += protocol
	s_addr = socket.inet_ntoa(iph[8]);
	d_addr = socket.inet_ntoa(iph[9]);
	print 'Source Address:',s_addr,'Destination Address',d_addr
	if(protocol == 17): #17 imples UDP
		print("UDP Packet")
		u = eth_length + iph_length #UDP Header Starting pointer
		udph_length = 8 #UDP Header Length
		udp_header = data[u:u+8] #UDP Header raw
		udph = unpack('!HHHH' , udp_header) #H for unsigned Short
		source_port = udph[0]
		dest_port = udph[1]
		length = udph[2]
		c_sum += length*2
		c_sum += source_port
		c_sum += dest_port
		checksum = udph[3] #This is the given checksum
		print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Given Checksum : ' + str(checksum)
		h_size = eth_length + iph_length + udph_length #Starting pointer for data
		data_size = len(packet) - h_size
		content = data[h_size:]
		if(len(content)%2 != 0):
			content+='\x00'
		print "Data is:",content
		i = 0
		while(i<len(content)-1):
			temp = unpack('!H',content[i:i+2])[0]
			c_sum += int(temp)
			i+=2
		c_sum = csummer(hex(c_sum))
		print 'Calculated Checksum is ',c_sum
		if(str(c_sum) == str(checksum)):
			print 'Valid Checksum'
		else:
			print 'Invalid Checksum'
	else:
		print("Not a UDP Packet")
def main():
	if(len(sys.argv) != 3 and sys.argv[1] != '-f'):
		print 'Please provide valid arguments'
		exit(0)
	filename = sys.argv[2]
	packetstream = getPacketStream(filename)
	packets = getPackets(packetstream)
	i=1
	for p in packets:
		print '###################PACKET-'+str(i)+'#####################'
		analyzePacket(p)
		i+=1
if __name__ == '__main__':
	main()