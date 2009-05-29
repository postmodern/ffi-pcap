require 'pcap/packets/typedefs'
require 'pcap/packet'

require 'ffi'

module FFI
  module PCap
    module Packets
      class Ethernet < FFI::Struct

        include Packet

        # Number of bytes for an ethernet address
        ADDR_LEN = 6

        # Size of an Ethernet header
        SIZE = 14

        layout :ether_dhost, [:uchar, ADDR_LEN],
               :ether_shost, [:uchar, ADDR_LEN],
               :ether_type, :ushort

        #
        # Returns the source MAC address.
        #
        def src_mac
          self[:ether_shost]
        end

        #
        # Returns the destination MAC address.
        #
        def dest_mac
          self[:ether_dhost]
        end

      end
    end
  end
end
