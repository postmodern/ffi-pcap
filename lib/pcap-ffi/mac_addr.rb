require 'ffi'

module FFI
  module PCap
    class MACAddr < FFI::Struct
      # Number of bytes for an ethernet address
      SIZE = 6

      layout :bytes, [FFI::NativeType::UINT8, SIZE]

      def self.parse(str)
        digits = str.split(':').map { |b| b.hex }
        mac = self.new

        mac[:bytes].to_ptr.put_array_of_uint8(0,digits[0,SIZE])
        return mac
      end

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

      def [](field)
        if field.kind_of?(Integer)
          return self.to_ptr.get_uint8(field)
        else
          return super(field)
        end
      end

      def []=(field,value)
        if field.kind_of?(Integer)
          self.to_ptr.put_uint8(field,value.to_i)
          return value
        else
          return super(field)
        end
      end

      def ==(other)
        self.to_a == other.to_a
      end

      def to_a
        self[:bytes].to_a
      end

      #
      # Converts the MAC address to hex form.
      #
      def to_s
        "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % self.to_a
      end

    end
  end
end
