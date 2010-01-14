
module FFI
  module PCap
    class Packet
      attr_reader :body_ptr

      def self.from_string(body, opts={})
        new(nil, body, opts)
      end

      # XXX do we need to worry about the timestamp for dumping? or is that 
      # automatically handled by libpcap when dumping.
      #
      # @param [PacketHeader, nil] hdr
      #   The pcap pkthdr struct for this packet or nil.  hdr may only be
      #   nil if a string is supplied for the body. A header will be 
      #   created automatically and set_body called with opts.
      #
      # @param [FFI::Pointer, String] body
      #   A string or pointer for the body of the packet. A String may
      #   only be specified if hdr is set to nil.
      #
      # @param [optional, Hash] opts
      #   Specifies additional options at creation time. Only those
      #   below are applicable for all initiatialization styles.
      #   All other options are sent to set_body(), but only if the header
      #   is nil and body is a String. See set_body() for more info.
      # 
      # @option opts [optional, Time] :time, :timestamp
      #   Sets the timestamp in the header.
      #
      # @raise [ArgumentError]
      #   An exception is raised if any of the parameter rules described 
      #   are not followed.
      #
      def initialize(hdr, body, opts={})
        o = opts.dup
        ts = o.delete(:time) || o.delete(:timestamp)
        case hdr
        when PacketHeader
          @header = hdr
        when FFI::Pointer
          @header = PacketHeader.new(hdr)
        when nil 
          if body.is_a? String
            set_body(body, o)
          else
            raise(ArgumentError, "can't set body to #{body.class}")
          end
        else
          raise(ArgumentError, "invalid header: #{hdr.class}")
        end
          
        @header.time = ts if ts

        unless @body_ptr
          if body.is_a?(FFI::Pointer)
            @body_ptr = body
          else
            raise(ArgumentError, "invalid body: #{body.class}")
          end
        end
      end

      # Sets the body from a string. A pointer is automatically derived from
      #
      # @param [String] data
      #   The body to set
      #
      # @param [Hash] opts
      #   Body length options.
      #
      # @option opts [optional, Integer] :caplen, :captured
      #   The captured length (or snaplen) for this packet.
      #   Length of data portion present. Defaults to body.size(). If
      #   caplen is larger than the body, then it is overridden with body.size.
      #   
      # @option opts [optional, Integer] :len, :length
      #   The total length of the packet (off wire). Defaults to caplen. If
      #   If :length is less than the :caplen, it is overridden as :caplen.
      #
      #
      # @return [String]
      #   Returns the data as supplied per attr_writer convention.
      #
      def set_body(data, opts={})
        cl = opts[:caplen] || opts[:captured] || data.size
        l = opts[:length] || opts[:len] || cl
        clen = (cl < data.size) ? cl : data.size
        len = (l < clen) ? clen : l

        @header ||= PacketHeader.new
        @header.caplen = len || @header.caplen
        @header.len = len || @header.caplen
        @body_ptr = FFI::MemoryPointer.from_string(data)
        return self
      end

      alias body= set_body

      # @return [String]
      #   A String representation of the packet data.
      #   The reference to the string is not kept by the object and changes
      #   won't affect the data in this packet.
      def body
        @body_ptr.read_string(@header.caplen)
      end

      # @return [Time]
      #   Returns the pcap timestamp as a Time object
      def time
        @header.ts.time
      end

      # Sets the pcap timestamp.
      def time=(t)
        @header.ts.time=(t)
      end

      def caplen
        @header.caplen
      end

      alias captured caplen

      def len
        @header.len
      end

      alias length len

      def copy
        self.class.new(nil, 
                       self.body, 
                       :caplen => @header.caplen, 
                       :len => @header.len)
      end

    end

  end
end
