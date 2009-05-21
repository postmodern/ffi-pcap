require 'pcap/typedefs'
require 'pcap/addr'

require 'ffi/struct'

module FFI
  module PCap
    class IF < FFI::Struct
      # interface is loopback
      LOOPBACK = 0x00000001

      layout :next, :pointer,
             :name, :string,
             :description, :string,
             :addresses, :pointer,
             :flags, :bpf_uint32

      def next
        IF.new(self[:next])
      end

      def addresses
        Addr.new(self[:addresses])
      end

    end
  end
end
