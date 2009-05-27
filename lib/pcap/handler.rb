require 'pcap/ffi'
require 'pcap/data_link'

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

      def initialize(pcap)
        @pcap = pcap
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

        return [header, data]
      end

      def open_dump(path)
        Dumper.new(PCap.pcap_dump_open(@pcap,File.expand_path(path)))
      end

      def stop
        PCap.pcap_breakloop(@pcap)
      end

      def close
        PCap.pcap_close(@pcap)
      end

      def inspect
        "#<#{self.class}: 0x#{@pcap.to_s(16)}>"
      end

    end
  end
end
