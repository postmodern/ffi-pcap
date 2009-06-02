require 'pcap_ffi/extensions/ffi/exceptions/unknown_endianness'

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
            num |= (bytes[i] << i * 8)
          end
        when :big
          return (0...length).inject(0) do |num,i|
            num |= (bytes[i] << ((length - i -1) * 8))
          end
        else
          raise(UnknownEndianness,"unknown endianness #{type}",caller)
        end
      end

    end
  end
end
