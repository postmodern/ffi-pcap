require 'pcap-ffi/typedefs'
require 'pcap-ffi/addr'

require 'ffi/struct'

module FFI
  module PCap

    # Item in a list of interfaces.
    #
    # See pcap_if struct in pcap.h
    class Interface < FFI::Struct
      include FFI::DRY::StructHelper

      # interface is loopback
      LOOPBACK = 0x00000001

      dsl_layout do
        p_struct  :next, Interface
        field     :name,        :string, :desc => 'name used by pcap_open_live()'
        field     :description, :string, :desc => 'text description, or NULL'
        p_struct  :addresses,   Addr,    :desc => 'address linked list'
        field     :flags,       :bpf_uint32, :desc => 'PCAP_IF_ interface flags'
      end

      def loopback?
        self.flags & LOOPBACK == LOOPBACK
      end

#      def to_s
#        self[:name]
#      end

    end

  end
end
