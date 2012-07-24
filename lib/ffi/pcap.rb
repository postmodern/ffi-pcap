require 'ffi_dry'

module FFI
  module PCap
    extend FFI::Library

    ffi_lib ['pcap', 'libpcap.so.1', 'wpcap']
  end

  Pcap = PCap
end

require 'ffi/pcap/crt'
require 'ffi/pcap/exceptions'

# FFI typedefs, pointer wrappers, and struct
require 'ffi/pcap/typedefs'
require 'ffi/pcap/bsd'
require 'ffi/pcap/addr'
require 'ffi/pcap/interface'
require 'ffi/pcap/file_header'
require 'ffi/pcap/time_val'
require 'ffi/pcap/packet_header'
require 'ffi/pcap/stat'
require 'ffi/pcap/bpf_instruction'
require 'ffi/pcap/bpf_program'
require 'ffi/pcap/dumper'

# Ruby FFI function bindings, sugar, and misc wrappers
require 'ffi/pcap/error_buffer'
require 'ffi/pcap/pcap'
require 'ffi/pcap/data_link'
require 'ffi/pcap/packet'
require 'ffi/pcap/live'
require 'ffi/pcap/offline'
require 'ffi/pcap/dead'
