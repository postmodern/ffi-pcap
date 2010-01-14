begin; require 'rubygems'; rescue LoadError; end

require 'ffi/dry'
require 'ffi/packets'

module FFI
  module PCap
    extend FFI::Library

    ffi_lib "libpcap"
  end
end

require 'pcap-ffi/version'
require 'pcap-ffi/exceptions'

# FFI typedefs, pointer wrappers, and struct
require 'pcap-ffi/typedefs'
require 'pcap-ffi/bsd'
require 'pcap-ffi/addr'
require 'pcap-ffi/interface'
require 'pcap-ffi/file_header'
require 'pcap-ffi/time_val'
require 'pcap-ffi/packet_header'
require 'pcap-ffi/stat'
require 'pcap-ffi/bpf'
require 'pcap-ffi/dumper'

# Ruby FFI function bindings, sugar, and misc wrappers
require 'pcap-ffi/error_buffer'
require 'pcap-ffi/pcap'
require 'pcap-ffi/data_link'
require 'pcap-ffi/packet'
require 'pcap-ffi/wrappers'
require 'pcap-ffi/live'
require 'pcap-ffi/offline'
require 'pcap-ffi/dead'

