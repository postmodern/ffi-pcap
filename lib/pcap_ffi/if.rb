require 'pcap_ffi/typedefs'
require 'pcap_ffi/addr'

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

      def name
        self[:name]
      end

      def addresses
        Addr.new(self[:addresses])
      end

      def to_s
        self[:name]
      end

    end
  end
end
