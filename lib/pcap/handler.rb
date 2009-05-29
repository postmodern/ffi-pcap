require 'pcap/exceptions/read_error'
require 'pcap/ffi'
require 'pcap/error_buffer'
require 'pcap/data_link'
require 'pcap/packet_header'
require 'pcap/stat'

require 'ffi'

module FFI
  module PCap
    class Handler

      include Enumerable

      # Default snaplen
      SNAPLEN = 65535

      # Pointer to the pcap opaque type
      attr_reader :pcap

      # Number of packets to sniff
      attr_accessor :count

      def initialize(pcap,options={},&block)
        @pcap = pcap

        # Default is to infinitely loop over packets.
        @count = (options[:count] || -1)

        if options[:direction]
          self.direction = options[:direction]
        end

        if block
          callback(&block)
        else
          # Default the callback to an empty Proc
          @callback = Proc.new {}
        end
      end

      def datalink
        DataLink.new(PCap.pcap_datalink(@pcap))
      end

      def callback(&block)
        if block
          @callback = block
        end

        return @callback
      end

      def direction=(dir)
        directions = PCap.enum_type(:pcap_direction)

        return PCap.pcap_setdirection(@pcap,directions[:"pcap_d_#{dir}"])
      end

      def non_blocking=(mode)
        errbuf = ErrorBuffer.new
        mode = if mode
          1
        else
          0
        end

        if PCap.pcap_setnonblock(@pcap,mode,errbuf) == -1
          raise(RuntimeError,errbuf.to_s,caller)
        end

        return mode == 1
      end

      def non_blocking?
        errbuf = ErrorBuffer.new
        mode = PCap.pcap_getnonblock(@pcap,errbuf)

        if mode == -1
          raise(RuntimeError,errbuf.to_s,caller)
        end

        return mode == 1
      end

      def loop(data=nil,&block)
        callback(&block) if block

        PCap.pcap_loop(@pcap,@count,@callback,data)
      end

      alias each loop

      def dispatch(data=nil,&block)
        callback(&block) if block

        PCap.pcap_dispatch(@pcap,@count,@callback,data)
      end

      def next
        header = PacketHeader.new
        data = PCap.pcap_next(@pcap,header)

        return [nil, nil] if data.null?
        return [header, data]
      end

      def next_extra
        header_ptr = MemoryPointer.new(:pointer)
        data_ptr = MemoryPointer.new(:pointer)

        case PCap.pcap_next_ex(@pcap,header_ptr,data_ptr)
        when -1
          raise(ReadError,"an error occurred while reading the packet",caller)
        when -2
          raise(ReadError,"the 'savefile' contains no more packets",caller)
        end

        return [header_ptr.get_pointer(0), data_ptr.get_pointer(0)]
      end

      def open_dump(path)
        dump_ptr = PCap.pcap_dump_open(@pcap,File.expand_path(path))

        if dump_ptr.null?
          raise(RuntimeError,error,caller)
        end

        return Dumper.new(dump_ptr)
      end

      def stats
        stats = Stat.new

        PCap.pcap_stats(@pcap,stats)
        return stats
      end

      def error
        PCap.pcap_geterr(@pcap)
      end

      def stop
        PCap.pcap_breakloop(@pcap)
      end

      def close
        PCap.pcap_close(@pcap)
      end

      def to_ptr
        @pcap
      end

      def inspect
        "#<#{self.class}: 0x#{@pcap.address.to_s(16)}>"
      end

    end
  end
end
