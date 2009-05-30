require 'pcap/packet'
require 'pcap/mac_addr'

module FFI
  module PCap
    module Packets
      class IEEE8023 < FFI::Struct

        include Packet

        layout :dest_mac, MACAddr,
               :src_mac, MACAddr,
               :length, [NativeType::UINT8, 2],
               :dsap, :uint8,
               :ssap, :uint8,
               :control, :uint8

        def dest_mac
          self[:dest_mac]
        end

        def src_mac
          self[:src_mac]
        end

        def length
          self[:length].to_endian(:big)
        end

        def dsap
          self[:dsap]
        end

        def ssap
          self[:ssap]
        end

        def control
          self[:control]
        end

      end
    end
  end
end
