require 'pcap/packet'
require 'pcap/mac_addr'

module FFI
  module PCap
    module Packets
      class IEEE8023 < FFI::Struct

        include Packet

        layout :dest_mac, MACAddr,
               :src_mac, MACAddr,
               :length, :uint16

        def dest_mac
          self[:dest_mac]
        end

        def src_mac
          self[:src_mac]
        end

        def length
          self[:length]
        end

      end
    end
  end
end
