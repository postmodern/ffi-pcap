#!/usr/bin/env ruby

require 'rubygems'
require 'pcap'

include FFI

pcap = PCap.open_live(:device => ARGV[0]) do |user,header,bytes|
  puts "#{header.timestamp}:"

  header.captured.times { |i|
    print ' %.2x' % bytes.get_uchar(i)
  }
  putc "\n"
end

pcap.loop
