require 'ffi'

module FFI
  module PCap
    module Packets
      class ICMPv4 < FFI::Struct
        class Echo < FFI::Struct

          layout :id, :uint16,
                 :sequence, :uint16

        end
      end
    end
  end
end
