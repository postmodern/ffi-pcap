require 'rubygems'
gem 'rspec', '>=1.2.9'
require 'spec'

require 'pcap-ffi'

include FFI
include FFI::PCap

PCAP_DEV = ENV['PCAP_DEV']
