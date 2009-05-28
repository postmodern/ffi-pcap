require 'pcap/packet'
require 'pcap/mac_addr'

require 'ffi'

module FFI
  module PCap
    module Packets
      class FDDI < FFI::Struct

        include Packet

        FC_VOID = 0x00
        FC_NON_RESTRICTED_TOKEN = 0x80
        FC_RESTRICTED_TOKEN = 0xc0
        FC_SMT_MIN = 0x41
        FC_SMT_MAX = 0x4f
        FC_MAC_MIN = 0xc1
        FC_MAC_MAX = 0xcf
        FC_ASYNC_LLC_MIN = 0x50
        FC_ASYNC_LLC_DEF = 0x54
        FC_ASYNC_LLC_MAX = 0x5f
        FC_SYNC_LLC_MIN = 0xd0
        FC_SYNC_LLC_MAX = 0xd7
        FC_IMPLEMENTOR_MIN = 0x60
        FC_IMPLEMENTOR_MAX = 0x6f
        FC_RESERVED_MIN = 0x70
        FC_RESERVED_MAX = 0x7f

        layout :fc, :uint8,
               :dhost, MACAddr,
               :shost, MACAddr

        def frame_control
          self[:fc]
        end

        def dest_host
          self[:dhost]
        end

        def src_host
          self[:shost]
        end

      end
    end
  end
end
