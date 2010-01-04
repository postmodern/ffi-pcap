require 'pcap-ffi/typedefs'
require 'pcap-ffi/addr'

require 'ffi/struct'

module FFI
  module PCap
    class IF < FFI::Struct
      include FFI::DRY::StructHelper

      # interface is loopback
      LOOPBACK = 0x00000001

      dsl_layout do
        p_struct  :next,      IF
        field     :name,      :string
        p_struct  :addresses, Addr
        field     :flags,     :bpf_uint32
      end

#      def to_s
#        self[:name]
#      end

    end
  end
end
