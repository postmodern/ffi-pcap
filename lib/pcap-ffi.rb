begin
  require 'rubygems'
rescue LoadError
end

require 'ffi/dry'
require 'ffi/packets'

module FFI::PCap
  extend FFI::Library

  ffi_lib 'libpcap'
end

require 'pcap-ffi/typedefs'
require 'pcap-ffi/if'
require 'pcap-ffi/bsd'
require 'pcap-ffi/addr'
require 'pcap-ffi/file_header'
require 'pcap-ffi/packet_header'
require 'pcap-ffi/stat'
require 'pcap-ffi/data_link'
require 'pcap-ffi/dumper'
require 'pcap-ffi/handler'
require 'pcap-ffi/version'
require 'pcap-ffi/pcap'

require 'pcap-ffi/ffi'
