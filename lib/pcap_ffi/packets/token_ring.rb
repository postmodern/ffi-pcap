require 'pcap_ffi/packet'
require 'pcap_ffi/mac_addr'

module FFI
  module PCap
    module Packets
      class TokenRing < FFI::Struct

        include Packet

        layout :ac, :uint8,
               :fc, :uint8,
               :daddr, MACAddr,
               :saddr, MACAddr,
               :rcf, [NativeType::UINT8, 2],
               :rseg, [NativeType::UINT16, 8]

        def access_control
          self[:ac]
        end

        def frame_control
          self[:fc]
        end

        def dest_addr
          self[:daddr]
        end

        def src_addr
          self[:src_addr]
        end

        def route_control
          self[:rcf]
        end

        def rseg
          self[:rseg]
        end

      end
    end
  end
end
