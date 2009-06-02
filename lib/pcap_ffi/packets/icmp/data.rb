require 'pcap_ffi/packets/icmp/echo'
require 'pcap_ffi/packets/icmp/frag'

require 'ffi'

module FFI
  module PCap
    module Packets
      class ICMPv4 < FFI::Struct
        class Data < FFI::Union
          layout :echo, Echo,
                 :gateway, :uint32,
                 :frag, Frag
        end
      end
    end
  end
end
