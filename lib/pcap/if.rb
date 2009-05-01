require 'pcap/typedefs'

require 'ffi/struct'

module FFI
  module PCap
    class IF < FFI::Struct
      # interface is loopback
      LOOPBACK = 0x00000001

      layout :pcap_if, :pointer,
             :name, :pointer,
             :description, :pointer,
             :addresses, :pointer,
             :flags, :bpf_uint32
    end
  end
end
