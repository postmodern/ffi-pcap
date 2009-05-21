require 'pcap/ffi'

require 'ffi'

module FFI
  module PCap
    class Handler < FFI::MemoryPointer

      include Enumerable

      attr_accessor :count

      def self.open_live(device,spanlen,promisc,to_ms)
      end

      def callback(&block)
        if block
          @callback = block
        end

        return @callback
      end

      def direction=(dir)
        PCap.pcap_setdirection(self,dir)
      end

      def loop(data,&block)
        callback(&block) if block

        PCap.pcap_loop(self,@count,@callback,data)
      end

      alias :each :loop

      def dispatch(data,&block)
        callback(&block) if block

        PCap.pcap_dispatch(self,@count,@callback,data)
      end

      def next
        header = PacketHeader.new
        data = PCap.pcap_next(self,header)

        return [header, data]
      end

      def stop
        PCap.pcap_breakloop(self)
      end

      def close
        PCap.pcap_close(self)
      end

    end
  end
end
