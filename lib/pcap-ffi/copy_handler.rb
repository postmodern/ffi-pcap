
module FFI
  module PCap

    # CopyHandler is a callback handler for use with CaptureWrapper.loop and 
    # CaptureWrapper.dispatch. When used, it works exactly as normal, 
    # passing a reference to a pcap wrapper and Packet except for one important
    # difference. A copy of the Packet is yielded to the callback instead of
    # the volatile one received in the pcap_loop() and pcap_dispatch() 
    # callbacks.
    #
    # The CopyHandler implements receive_callback to return a _copy_
    # of the Packet object. It is necessary to make a copy to keep allocated
    # references to packets supplied by pcap_loop() and pcap_dispatch() 
    # callbacks outside of the scope of a single callback firing on one
    # packet.
    #
    # This handler interface is used by default by CaptureWrapper, so it is
    # generally always safe to keep references to received packets after new
    # packets have been received or even after a pcap interface has been 
    # closed. See CaptureWrapper for more information.
    class CopyHandler < Handler
      def receive_pcap(pcap, phdr, bufp, tag=nil)
        return [pcap, Packet.allocate(phdr, bufp)]
      end
    end
  end
end
