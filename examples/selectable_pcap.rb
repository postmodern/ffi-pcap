#!/usr/bin/env ruby

$: << File.expand_path( File.join(File.dirname(__FILE__), '../lib'))

require 'ffi/pcap'
require 'eventmachine'

dev = ARGV.shift || 'lo0'
if ARGV[0]
  filter = ARGV.join(' ')
end

EM.run{
  pcap = FFI::PCap::Live.new(:device => dev, :timeout => 1)
  pcap.nonblocking=true
  pcap.setfilter filter if filter

  fd = pcap.fileno
  io=IO.new(fd)
  while Kernel.select([io],nil,nil)
    p :meep
    pcap.dispatch() do |this,pkt| 
      puts pkt.time
      puts pkt.body.bytes.map{|x| "%0.2x" % x}.join(' ')
    end
  end
}

