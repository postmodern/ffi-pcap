
module FFI
  module PCap
    class Packet
      attr_reader :header, :body_ptr

      def self.from_string(body)
        new(PacketHeader.new(), body.to_s)
      end

      # XXX do we need to worry about the timestamp for dumping? or is that 
      # automatically handled by libpcap when dumping.
      #
      # @param [PacketHeader] hdr
      #   The pcap pkthdr struct for this packet.
      #
      # @param [FFI::Pointer, String] body
      #   A string or pointer for the body of the packet.
      #
      def initialize(hdr, body)
        @header = 
          case hdr
          when PacketHeader
            hdr
          when FFI::Pointer
            PacketHeader.new(hdr)
          else
            raise(ArgumentError, "invalid hdr: #{hdr.inspect}")
          end
          
        @body_ptr = 
          case body
          when FFI::Pointer
            body
          when String
            self.body = body
          else
            raise(ArgumentError, "invalid body: #{body.inspect}")
          end
      end

      # Sets the body pointer. For use with PCap::Dumper
      #
      # @param [FFI::Pointer] ptr
      #   A pointer to the body data.
      #
      # @param [Integer] caplen
      #   Length of data portion present. This parameter is always required.
      #
      # @param [optional, Integer] len
      #   Length of packet (off wire). Defaults to caplen.
      #
      # @return [self]
      #
      def set_body_ptr(ptr, caplen, len=nil)
        @header.caplen = caplen
        @header.len = len || caplen
        @body_ptr = ptr
        return self
      end

      # Sets the body from a string. A pointer is automatically derived from
      # the string and stored as an instance variable. For use with PCap::Dumper.
      #
      # @param [String] data
      #   The body to set
      #
      # @param [optional, Integer] caplen
      #   Length of data portion present. Defaults to body.size()
      #   
      # @param [optional, Integer] len
      #   Length of data in packet (off wire). Defaults to caplen
      #
      # @return [String]
      #   Returns the data as supplied per attr_writer convention.
      #
      def set_body(data, caplen=nil, len=nil)
        @header.caplen = 
          if caplen.nil? or caplen > data.size
            data.size
          else
            caplen
          end

        @header.len = len || @header.caplen
        @body_ptr = FFI::MemoryPointer.from_string(data)
        return data
      end

      alias body= set_body

      def body
        @body_ptr.read_string(@header.caplen)
      end

      def time
        @header.ts.time
      end

      def time=(t)
        @header.ts.time=(t)
      end
    end

  end
end
