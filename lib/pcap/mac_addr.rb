require 'ffi'

module FFI
  module PCap
    class MACAddr < FFI::Struct
      # Number of bytes for an ethernet address
      SIZE = 6

      layout :bytes, [:uchar, SIZE]

      #
      # Returns +true+ if the MAC is a broadcast address, returns +false+
      # otherwise.
      #
      def broadcast?
        self[:bytes].each do |b|
          return false unless b == 0xff
        end

        return true
      end

      #
      # Converts the MAC address to hex form.
      #
      def to_s
        "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % self[:bytes].to_a
      end

    end
  end
end
