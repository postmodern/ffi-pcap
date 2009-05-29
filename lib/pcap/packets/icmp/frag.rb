require 'ffi'

module FFI
  module PCap
    module Packets
      class ICMPv4 < FFI::Struct
        class Frag < FFI::Struct

          layout :unused, :uint16,
                 :mtu, :uint16

        end
      end
    end
  end
end
