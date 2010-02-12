require 'rubygems'
gem 'rspec', '>=1.3.0'
require 'spec'

require 'pcap-ffi/version'

include FFI
include FFI::PCap

PCAP_DEV = ENV['PCAP_DEV']
