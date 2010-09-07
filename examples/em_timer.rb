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
  pcap.setfilter filter if filter

  timer = EM::PeriodicTimer.new(0.0001) do
    puts "Dispatch!" if $DEBUG
    pcap.dispatch(:count => -1) do |this, pkt|
      puts "#{pkt.time}:"
      puts pkt.body.bytes.to_a.map{|c|  "%0.2x" % c }.join(" ")
    end
    puts "end dispatch" if $DEBUG
  end
}

