#!/usr/bin/env ruby

$: << File.expand_path( File.join(File.dirname(__FILE__), '../lib'))

require 'rubygems'
require 'ffi/pcap'
require 'eventmachine'

class PcapWatcher < EM::Connection
  def initialize(pcap)
    @pcap = pcap
  end

  def notify_readable(*args)
    puts "Dispatch!"
    @pcap.dispatch() do |this, pkt|
      puts "#{pkt.time}:"
      puts pkt.body.bytes.to_a.map{|c|  "%0.2x" % c }.join(" ")
    end
    puts "end dispatch"
  end

end

dev = ARGV.shift || 'lo0'
if ARGV[0]
  filter = ARGV.join(' ')
end

EM.run{
  pcap = FFI::PCap::Live.new(:device => dev, :timeout => 1)
  pcap.nonblocking=true
  pcap.setfilter filter if filter

  conn = EM.watch pcap.selectable_fd, PcapWatcher, pcap
  conn.notify_readable = true
}

