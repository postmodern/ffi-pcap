begin; require 'rubygems'; rescue LoadError; end

require 'ffi_dry'

module FFI
module PCap
  extend FFI::Library

  begin
    ffi_lib "wpcap"
  rescue LoadError
    ffi_lib "pcap"
  end
end
end

require 'ffi/pcap/crt'

require 'ffi/pcap/version'
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
require 'ffi/pcap/bpf'
require 'ffi/pcap/dumper'

# Ruby FFI function bindings, sugar, and misc wrappers
require 'ffi/pcap/error_buffer'
require 'ffi/pcap/pcap'
require 'ffi/pcap/data_link'
require 'ffi/pcap/packet'
require 'ffi/pcap/live'
require 'ffi/pcap/offline'
require 'ffi/pcap/dead'

