require 'pcap/packet'

module FFI
  module PCap
    module Packets
      class Raw

        include Packet

        def size
          0
        end

        def to_ptr
          @payload.to_ptr
        end

      end
    end
  end
end
