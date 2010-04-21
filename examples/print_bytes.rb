#!/usr/bin/env ruby

require 'rubygems'
require 'caper'

pcap =
  Caper::Live.new(:dev => 'en0', 
                 :promisc => true, 
                 :handler => Caper::Handler)

pcap.loop() do |this,pkt|
  puts "#{pkt.time}:"

  pkt.captured.times {|i| print ' %.2x' % pkt.body_ptr.get_uchar(i) }
  putc "\n"
end

