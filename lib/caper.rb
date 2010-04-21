begin; require 'rubygems'; rescue LoadError; end

require 'ffi_dry'

module Caper
  extend FFI::Library

  begin
    ffi_lib "wpcap"
  rescue LoadError
    ffi_lib "pcap"
  end
end

require 'caper/crt'

require 'caper/version'
require 'caper/exceptions'

# FFI typedefs, pointer wrappers, and struct
require 'caper/typedefs'
require 'caper/bsd'
require 'caper/addr'
require 'caper/interface'
require 'caper/file_header'
require 'caper/time_val'
require 'caper/packet_header'
require 'caper/stat'
require 'caper/bpf'
require 'caper/dumper'

# Ruby FFI function bindings, sugar, and misc wrappers
require 'caper/error_buffer'
require 'caper/pcap'
require 'caper/data_link'
require 'caper/packet'
require 'caper/live'
require 'caper/offline'
require 'caper/dead'

