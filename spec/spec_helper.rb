require 'rubygems'
gem 'rspec', '>=1.2.9'
require 'spec'

require 'pcap-ffi'

include FFI
include FFI::PCap

PCAP_DEV      = ENV['PCAP_DEV'] || 'lo0'
PCAP_TESTFILE = ENV['PCAP_DEV'] || File.expand_path(File.join(File.dirname(__FILE__), 'dumps', 'simple_tcp.pcap'))
