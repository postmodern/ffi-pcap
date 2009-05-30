require 'pcap/extensions/ffi/exceptions/unknown_endianness'

require 'rubygems'
require 'ffi'

module FFI
  class Struct
    class Array

      def to_endian(type)
        length = self.size
        bytes = self.to_ptr.get_array_of_uint8(0,length)

        case type.to_sym
        when :little, :network
          return (0...length).inject(0) do |num,i|
            num |= (bytes[i] << (length - i))
          end
        when :big
          return (0...length).inject(0) do |num,i|
            num |= (bytes[i] << i)
          end
        else
          raise(UnknownEndianness,"unknown endianness #{type}",caller)
        end
      end

    end
  end
end
