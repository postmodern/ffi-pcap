# -*- ruby -*-

require 'rubygems'
Dir["tasks/*.rb"].each {|rt| require rt }
require 'rake/clean'
require './lib/pcap-ffi/version.rb'

# Generate a gem using jeweler
begin
  require 'jeweler'
  Jeweler::Tasks.new do |gemspec|
    gemspec.rubyforge_project = 'pcap-ffi'
    gemspec.name = "pcap-ffi"
    gemspec.summary = "FFI bindings for libpcap"
    gemspec.email = "postmodern.mod3@gmail.com"
    gemspec.homepage = "http://github.com/postmodern/pcap-ffi"
    gemspec.description = "Bindings to sniff packets using the FFI interface in Ruby."
    gemspec.authors = ["Postmodern, Dakrone", "Eric Monti"]
    gemspec.add_dependency "ffi"
    gemspec.add_dependency "ffi_dry"
  end
rescue LoadError
  puts "Jeweler not available. Install it with: sudo gem install technicalpickles-jeweler -s http://gems.github.com"
end

# vim: syntax=Ruby
