require 'rubygems'
gem 'rspec', '>=1.1.12'
require 'spec'

require 'pcap_ffi/version'

include FFI
include FFI::PCap

PCAP_DEV = ENV['PCAP_DEV']
