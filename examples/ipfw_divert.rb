#!/usr/bin/env ruby
#
# Thanks to justfalter(Mike Ryan) for turning me onto Divert Sockets for
# this example.
#
# ipfw add tee 6666 tcp from 192.168.63.128 to any
# ipfw add tee 6666 tcp from any to 192.168.63.128

require 'caper'
require "socket"
require 'pp'

unless Process::Sys.getuid == 0  
  $stderr.puts "Must run #{$0} as root."
  exit!
end

IPPROTO_DIVERT = 254

outfile = ARGV.shift
#outfile = "test_#{$$}.pcap"

# create a dummy pcap handle for dumping
pcap        = Caper.open_dead(:datalink => :raw)
pcap_dumper = pcap.open_dump(outfile)

begin 
  divert_sock = Socket.open(Socket::PF_INET, Socket::SOCK_RAW, IPPROTO_DIVERT)
  sockaddr = Socket.pack_sockaddr_in( 6666, '0.0.0.0' )
  divert_sock.bind(sockaddr)

  puts "ready and waiting...."

  while IO.select([divert_sock], nil, nil)
    data = divert_sock.recv(65535) # or MTU?
    pp data
    pcap_dumper.write_pkt( Caper::Packet.from_string(data) )
    pcap_dumper.flush 
  end
rescue Errno::EPERM
  $stderr.puts "Must run #{$0} as root."
  exit!
ensure 
  puts "Closing socket."
  divert_sock.close
  puts "Closing pcap dumper."
  pcap_dumper.close
  pcap.close
end
