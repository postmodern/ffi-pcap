require 'pcap_ffi/exceptions/read_error'
require 'pcap_ffi/ffi'
require 'pcap_ffi/error_buffer'
require 'pcap_ffi/data_link'
require 'pcap_ffi/packet_header'
require 'pcap_ffi/stat'
require 'pcap_ffi/packets/raw'

require 'ffi'

module FFI
  module PCap
    class Handler

      include Enumerable

      # Default snaplen
      SNAPLEN = 65535

      # Pointer to the pcap opaque type
      attr_reader :pcap

      # DataLink for the pcap descriptor
      attr_reader :datalink

      # Number of packets to sniff
      attr_accessor :count

      def initialize(pcap,options={},&block)
        @pcap = pcap
        @datalink = DataLink.new(PCap.pcap_datalink(@pcap))

        @closed = false

        # Default is to infinitely loop over packets.
        @count = (options[:count] || -1)

        if options[:direction]
          self.direction = options[:direction]
        end

        @callback_wrapper = Proc.new do |user,pkthdr,bytes|
          if @callback
            header = PacketHeader.new(pkthdr)
            raw = Packets::Raw.new(bytes,header.captured,@datalink)

            @callback.call(user,header,raw)
          end
        end

        callback(&block)

        trap('SIGINT',&method(:close))
        trap('SIGTERM',&method(:close))
      end

      def callback(&block)
        @callback = block
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

        PCap.pcap_loop(@pcap,@count,@callback_wrapper,data)
      end

      alias each loop

      def dispatch(data=nil,&block)
        callback(&block) if block

        return PCap.pcap_dispatch(@pcap,@count,@callback_wrapper,data)
      end

      def next
        header = PacketHeader.new
        bytes = PCap.pcap_next(@pcap,header)

        return [nil, nil] if bytes.null?

        raw = Packets::Raw.new(bytes,header.captured,@datalink)
        return [header, raw]
      end

      def next_extra
        header_ptr = MemoryPointer.new(:pointer)
        bytes_ptr = MemoryPointer.new(:pointer)

        case PCap.pcap_next_ex(@pcap,header_ptr,bytes_ptr)
        when -1
          raise(ReadError,"an error occurred while reading the packet",caller)
        when -2
          raise(ReadError,"the 'savefile' contains no more packets",caller)
        end

        header = header_ptr.get_pointer(0)
        raw = Packets::Raw.new(bytes_ptr.get_pointer(0),header.captured,@datalink)

        return [header, raw]
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

      def closed?
        @closed == true
      end

      def close
        unless @closed
          @closed = true
          PCap.pcap_close(@pcap)
        end
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
