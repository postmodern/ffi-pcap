require 'ffi'

module FFI
  module PCap
    class MACAddr < FFI::Struct
      # Number of bytes for an ethernet address
      SIZE = 6

      layout :bytes, [:uchar, SIZE]

      #
      # Converts the MAC address to hex form.
      #
      def to_s
        "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % self[:bytes].to_a
      end

    end
  end
end
