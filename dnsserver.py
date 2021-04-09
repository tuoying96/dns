import sys
import socketserver
import struct
import socket
import json
from random import * 

# UDP_IP = "cs5700cdnproject.ccs.neu.edu"
UDP_IP = "129.10.117.187"

# For message
_DNS = "DNS_SIDE"
_REPLICA = "REPLICA_SIDE"

# For message TYPE
_PUT_CLIENT = 1
_GET_REPLICA = 2
_OK = 3

_LIST_CLIENTS = 4
_UPDATE_CLIENTS = 5

class CDNLogic:

    def __init__(self):
        self.EC2_HOSTS = {'ec2-34-201-72-189.compute-1.amazonaws.com':'34.201.72.189'}
        self.coords = {'34.201.72.189':[]}

    def find_best_replica(self, client_addr):
        return '34.201.72.189'

class Packet():
    """
    DNS Packet Structure: https://www2.cs.duke.edu/courses/fall16/compsci356/DNS/DNS-primer.pdf
    
    'The unsigned fields query count (QDCOUNT), answer count (ANCOUNT),
    authority count (NSCOUNT), and additional information count (ARCOUNT)
    express the number of records in each section for all opcodes'
    
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                QDCOUNT/ZOCOUNT                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                ANCOUNT/PRCOUNT                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                NSCOUNT/UPCOUNT                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    DNS Questions
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               | A domain name represented as a sequence of labels, 
    /                     QNAME                     / where each label consists of a length octet followed by that number of octets. 
    /                                               / The domain name terminates with the zero length octet for the null label of the root. 
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     | A two octet code which specifies the type of the query
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    | A two octet code that specifies the class of the query.
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    DNS Answers
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               / The domain name that was queried, in the same format as the QNAME in the questions.
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     | The RR type, for example, A or AAAA
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     | The RR class, for instance, Internet
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      | The number of seconds the results can be cached.
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    | The length of RR specific data in octets
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     / Actual Resource Record data (IP address). The data of the response.
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """
    # the constructor of Packet
    def __init__(self):
        self.id = randint(0, 65535)
        self.flags = 0
        self.qd_count = 0
        self.an_count = 0
        self.ns_count = 0
        self.ar_count = 0
        self.q_name = ''
        self.q_type = 0
        self.q_class = 0
        self.an_type = 0
        self.an_type = 0
        self.an_class = 0
        self.an_ttl = 0
        self.an_len = 0
        self.data = '' 



    def pack_packet( self, domain, ip ):
        self.an_count = 1 # One answer will be returned
        self.flags = 0x8180 # Bits set: QR (query response), RD (recursion desired), RA (recursion available)

        # generate question 
        header = struct.pack('>HHHHHH', self.id, self.flags,
                             self.qd_count, self.an_count,
                             self.ns_count, self.ar_count)
        
        self.q_name = domain
        query = ''.join(chr(len(x)) + x for x in self.q_name.split('.'))
        query += '\x00'  # add end symbol
        query_part =  query.encode('utf-8') + struct.pack('>HH', self.q_type, self.q_class)

        self.an_name = 0xC00C # Pointer to qname label: 1100 0000 0000 1100
        self.an_type = 0x0001 # The A record for the domain name
        self.an_class = 0x0001 # Internet (IP)
        self.an_ttl = 60  # time to live, 32-bit value
        self.an_len = 4 # IP address is 32 bits or 4 bytes, but the length field is 16 bits.
        self.data = ip
        answer_part = struct.pack( '>HHHLH4s', self.an_name, self.an_type, self.an_class,
                          self.an_ttl, self.an_len, socket.inet_aton( ip ) )

        packet = header + query_part + answer_part

        return packet

    def unpack_packet( self, data ):

        [self.id,
        self.flags,
        self.qd_count,
        self.an_count,
        self.ns_count,
        self.ar_count] = struct.unpack('>HHHHHH', data[0:12]) # OR struct.unpack('!6H', packet[0:12])

        query_data = data[ 12: ] # DNS query
        [self.q_type, self.q_class] = struct.unpack('>HH', query_data[-4:])
        s = query_data[:-4] # This is qname in the DNS packet diagram above.
        ptr = 0
        temp = []
        print("s is: ", s)
        while True:
            count = s[ptr]
            # count = ord( s[ptr] )
            if count == 0:
                break
            ptr += 1
            temp.append(s[ ptr:ptr + count].decode('utf-8'))
            ptr += count
            # type(temp)
            # print(temp)
        self.q_name = '.'.join(temp)
        print ("DEBUG: self.q_name: " + self.q_name)
    
    def debug(self):
        print ("ID: %X, Flags: %X" % (self.id, self.flags))
        print ("Qcount: %d, Acount: %d, NS: %d, AR: %d" % (self.qd_count, self.an_count, self.ns_count, self.ar_count))
        print ("Qname: %s, Qtype: %X, Qclass: %X" % (self.q_name, self.q_type, self.q_class))
        print ("Aname: %X, Atype: %X, Aclass: %X" % (self.an_name, self.an_type, self.an_class))
        print ("TTL: %d, Length: %X, IP: %s" % (self.an_ttl, self.an_len, self.data))

# Put a datagram socket into this class also to send and receive
# request to map.py. map.py should be a server running on the same
# host ( on a different port ) and handle the latency of clients and 
# replicas. 

class DNSServer:
    def __init__(self, name, port):
        self.name = name
        self.port = int(port)
        self.my_ip = self.get_ipaddr()
        self.cdn_logic = CDNLogic()
        self.client_locations = {} # Stores mappings from clients to their closest replica
        self.sock = -1
        print ("DEBUG: name: %s, port: %s, my_ip: %s" % (self.name, self.port, self.my_ip))
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            self.sock.bind((self.my_ip, self.port))
        except socket.error as e:
            print("Failed to set up sockets. The error message is: ", e)
            sys.exit()

    def get_ipaddr(self):
        """Find IP address of the local machine."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # s.connect(('google.com', 80)) # cs5700cdnproject.ccs.neu.edu

        s.connect(('cs5700cdnproject.ccs.neu.edu', 8080)) # cs5700cdnproject.ccs.neu.edu
        # Note that the origin server ？？？ is running a Web server on port 8080, not 80. 
        ip = s.getsockname()[0]
        s.close()
        return ip

    def run_server(self):
        """Runs in an infinite loop, getting DNS requests from hosts and spawning
            a new thread to actually process the data."""
        while True:
            request, client = self.sock.recvfrom(65535)
            print("DEBUG: request:", request, "client: ", client)
            self.handle_request(request, client)
            # try:          
            #     request, client = self.sock.recvfrom(65535)
            #     print("DEBUG: request:", request, "client: ", client)
            #     self.handle_request(request, client)
		    #     #print request
            #     # thread.start_new_thread = (self.handle_request, request, client)
            # except:
            #     sys.exit("Error receiving data or creating thread.")
        

    def handle_request(self, request, client):
        # data = self.request[0].strip()
        # sock = self.request[1]

        packet = Packet()
        packet.unpack_packet(request)
 

        if client[0] in self.client_locations:
            best_server = self.client_locations[client[0]]
        else:
            best_server = self.cdn_logic.find_best_replica(client[0])
            self.client_locations[client[0]] = best_server

        dns_response = packet.pack_packet(self.name, best_server)
        print("dns_response", dns_response)

        self.sock.sendto(dns_response, client)

        try:
            self.sock.sendto(dns_response, client)
        except socket.error as e:
            print("Failed to send DNS Answer. The error message is: ", e)
            sys.exit()

        ################
        
        # if packet.q_type == 1 and packet.q_name == self.server.name:
        #     print ("DEBUG: Should reply to: " + str(self.client_address))
        #     ip = self.server.mapContacter.select_best_replica( self.client_address )
        #     response = packet.packPacket( ip )

        #     sock.sendto(response, self.client_address)
        #     self.server.mapContacter.addClient( self.client_address )

def getPortAndName( argv ):
    if len( argv ) != 5 or argv[ 1 ] != "-p" or argv[ 3 ] != "-n":
        sys.exit( "Usage: ./dnsserver -p [port] -s [name]" )
    port = int( argv[ 2 ] )
    name = argv[ 4 ]
    return port, name

if __name__ == '__main__':
    port, name = getPortAndName( sys.argv )
    dns_server = DNSServer( name, port )
    dns_server.run_server()

# ./dnsserver -p <port> -n <name>
# ./dnsserver -p 8080 -n cs5700cdnproject.ccs.neu.edu
# ./dnsserver -p 40008 -n http://ec2-34-201-72-189.compute-1.amazonaws.com/

# ./dnsserver -p 40008 -n cs5700cdnproject.ccs.neu.edu

# dig @10.15.184.38 -p 40008 -n cs5700cdn.example.com
# dig @192.168.0.178 -p 40008 -n cs5700cdn.example.com

# scp -i /Users/cortey/.ssh/id_ed25519 /Users/cortey/Documents/GitHub/cs5700_21spring/project5/dnsserver.py tuoying96@ec2-54-159-99-25.compute-1.amazonaws.com
