require 'pcap/typedefs'

require 'ffi/struct'

module FFI
  module PCap
    class Addr < FFI::Struct
      layout :pcap_addr, :pointer,
             :addr, :pointer,
             :netmask, :pointer,
             :broadaddr, :pointer,
             :dstaddr, :pointer
    end
  end
end
