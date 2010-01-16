
module FFI
  module PCap
    callback :pcap_handler, [:pointer, PacketHeader, :pointer], :void

    # The Handler class implements the pcap_handler interface using Ruby Proc
    # objects. For convenience, the handler encapsulates pkthdr and packet 
    # bytes obtained from the callback into a Packet object instead of their
    # raw memory pointers. 
    #
    # Neither pcap_loop() nor pcap_dispatch() guarantee allocated memory for 
    # each packet received, so it is up to the caller to retain a copy outside
    # the scope of the Handler block. See CopyHandler for a version of the 
    # Handler that does this automatically before yielding to the callback.
    #
    # It is recommended that for safety, CopyHandler be used in most situations.
    # However the direct Handler class is still available for high performance
    # needs since it may save some processing by not copying each packet.
    class Handler
      attr_reader :handler

      def initialize(wrapper, block)
        unless wrapper.kind_of?(CaptureWrapper)
          raise(TypeError, "expected wrapper to be a FFI::CaptureWrapper")
        end

        @pcap = wrapper
        @handler = block
      end

      def callback
        method(:receive_callback)
      end

      def receive_callback(id, pkthdr_p, bytes_p)
        @handler.call(@pcap, Packet.new(pkthdr_p, bytes_p))
      end

    end

    # CopyHandler works exactly the same as Handler, except for one important
    # difference. A copy of the packet is yielded to the callback instead of
    # the temporary one received in the pcap_loop() and pcap_dispatch() 
    # callbacks.
    #
    # The CopyHandler overrides receive_callback to return a _copy_
    # of the packet object. It is necessary to make a copy to keep allocated
    # references to packets supplied by pcap_loop() and pcap_dispatch() 
    # callbacks outside of the scope of a single callback firing on one
    # packet.
    #
    # Use this handler interface if you intend to keep a reference to received
    # packets after new packets have been received or even after you close
    # a pcap interface.
    class CopyHandler < Handler
      def receive_callback(id, pkthdr, bytes)
        @handler.call(@pcap, Packet.allocate(pkthdr, bytes))
      end
    end
  end
end
