require 'pcap/packets/typedefs'

require 'ffi'

module FFI
  module PCap
    module Packets
      class Ethernet < FFI::Struct

        ADDR_LEN = 6

        SIZE = 14

        layout :ether_dhost, [:uchar, ADDR_LEN],
               :ether_shost, [:uchar, ADDR_LEN],
               :ether_type, :ushort

        def src_mac
          self[:ether_shost]
        end

        def dest_mac
          self[:ether_dhost]
        end

      end
    end
  end
end
