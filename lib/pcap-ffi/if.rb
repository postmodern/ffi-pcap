require 'pcap-ffi/typedefs'
require 'pcap-ffi/addr'

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

      # The next IF in the list or nil if this is the last.
      #
      # @return [IF, nil]
      def next
        IF.new(self[:next]) unless self[:next].null?
      end

      # Device name
      #
      # @return [String]
      def name
        self[:name]
      end

      # Addresses for this device.
      #
      # @return [Addr]
      def addresses
        Addr.new(self[:addresses])
      end

      def to_s
        self[:name]
      end

    end
  end
end
