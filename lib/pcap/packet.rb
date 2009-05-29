module FFI
  module PCap
    module Packet
      #
      # Returns the data payload of the packet.
      #
      def payload
        self + self.size
      end
    end
  end
end
