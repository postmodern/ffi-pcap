#!/usr/bin/env ruby
$: << File.expand_path( File.join(File.dirname(__FILE__), '../lib'))

require 'rubygems'
require 'ffi/pcap'

dev = ARGV.shift || 'lo0'

pcap =
  FFI::PCap::Live.new(:dev => dev, 
                      :timeout => 1,
                 :promisc => true, 
                 :handler => FFI::PCap::Handler)

pcap.loop() do |this,pkt|
  puts "#{pkt.time}:"

  pkt.captured.times {|i| print ' %.2x' % pkt.body_ptr.get_uchar(i) }
  putc "\n"
end

