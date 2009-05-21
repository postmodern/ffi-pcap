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

      def self.open_live(options={})
        device = options[:device]
        promisc = if options[:promisc]
                    1
                  else
                    0
                  end
        snaplen = (options[:snaplen] || SNAPLEN)
        to_ms = (options[:timeout] || 0)

        ptr = PCap.pcap_open_live(device,snaplen,promisc,to_ms,nil)

        unless ptr
          raise(StandardError,errbuf,caller)
        end

        return self.new(ptr)
      end

      def self.open_dead(datalink,snaplen=SNAPLEN)
        datalink = DataLink[datalink]

        return self.new(PCap.pcap_open_dead(datalink,snaplen))
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
        PCap.pcap_setdirection(@pcap,dir)
      end

      def loop(data,&block)
        callback(&block) if block

        PCap.pcap_loop(@pcap,@count,@callback,data)
      end

      alias :each :loop

      def dispatch(data,&block)
        callback(&block) if block

        PCap.pcap_dispatch(@pcap,@count,@callback,data)
      end

      def next
        header = PacketHeader.new
        data = PCap.pcap_next(@pcap,header)

        return [header, data]
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
