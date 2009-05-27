# -*- ruby -*-

require 'rubygems'
require './lib/pcap/version.rb'
require './tasks/spec.rb'

# Generate a gem using jeweler
begin
  require 'jeweler'
  Jeweler::Tasks.new do |gemspec|
    gemspec.name = "pcap-ffi"
    gemspec.summary = "FFI bindings for libpcap"
    gemspec.email = "lee@writequit.org"
    gemspec.homepage = "http://github.com/dakrone/pcap-ffi"
    gemspec.description = "Bindings to sniff packets using the FFI interface in Ruby."
    gemspec.authors = ["Postmodern, Dakrone"]
  end
rescue LoadError
  puts "Jeweler not available. Install it with: sudo gem install technicalpickles-jeweler -s http://gems.github.com"
end


# vim: syntax=Ruby
