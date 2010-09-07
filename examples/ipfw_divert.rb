#!/usr/bin/env ruby
#
# Thanks to justfalter(Mike Ryan) for turning me onto Divert Sockets for
# this example.
#
# This demos the ability to use PCAP dump to write a pcap file with
# packets captured using a divert socket. In order to generate 
# packets that are diverted you need a system that supports IPFW
# and you need to establish some ipfw rules that divert packets to
# a chosen 
#
# ipfw add tee 6666 tcp from 192.168.63.128 to any
# ipfw add tee 6666 tcp from any to 192.168.63.128

$: << File.expand_path( File.join(File.dirname(__FILE__), '../lib'))

require 'rubygems'
require 'ffi/pcap'
require "socket"
require 'pp'
IPPROTO_DIVERT = 254

unless Process::Sys.getuid == 0  
  $stderr.puts "Must run #{$0} as root."
  exit!
end

outfile = ARGV.shift
my_divert_port = ARGV.shift || 6666

# create a dummy pcap handle for dumping
puts "Dumping packets to #{outfile}"
pcap        = FFI::PCap.open_dead(:datalink => :raw)
pcap_dumper = pcap.open_dump(outfile)

begin 
  divert_sock = Socket.open(Socket::PF_INET, Socket::SOCK_RAW, IPPROTO_DIVERT)
  sockaddr = Socket.pack_sockaddr_in( my_divert_port, '0.0.0.0' )
  divert_sock.bind(sockaddr)

  puts "IPFW divert socket is listening. Press ctrl-C to end capture"

  while IO.select([divert_sock], nil, nil)

    data = divert_sock.recv(65535) # or MTU?
    pp data
    pcap_dumper.write_pkt( FFI::PCap::Packet.from_string(data) )
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
