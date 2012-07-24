require 'ffi/pcap/common_wrapper'
require 'ffi/pcap/copy_handler'

module FFI
  module PCap
    #
    # A superclass for both offline and live interfaces, but not dead
    # interfaces. This class provides all the features necessary for
    # receiving packets through libpcap.
    #
    # The loop and dispatch methods default to using a {CopyHandler} object
    # when preparing values to the callback block. This is done to safely 
    # provide references to packets outside of the callback blocks.  
    # See CopyHandler for more information. 
    #
    # Note that for performance reasons, you may not need or want to incur 
    # the extra overhead of creating a copy for every Packet. You can supply
    # a `nil` value for the loop handler which will simply pass volatile 
    # references to packets directly to your block. You can also write
    # custom handlers which implement the `receive_pcap` method and
    # implement custom defined behaviors.
    #
    class CaptureWrapper < CommonWrapper

      include Enumerable

      # Default packet count (-1: infinite loop)
      DEFAULT_COUNT = -1

      attr_accessor :handler

      #
      # Adds an extra parameter :handler for specifying a capture handler
      # when using loop or dispatch. The handler defaults to {CopyHandler},
      # which always yields a copy of each packet to a block.
      #
      # Setting :handler to `nil` will pass packets directly to a block
      # without copying them, which may be desirable if the packets are
      # only ever processed within the block, and code does not need to
      # retain a reference to them elsewhere.
      #
      def initialize(pcap, opts={}, &block)
        @handler = opts.fetch(handler,CopyHandler)

        trap('INT') do
          stop()
          close()

          raise(SignalException,'INT',caller)
        end

        trap('TERM') do
          stop()
          close()

          raise(SignalException,'TERM',caller)
        end

        super(pcap, opts, &block)
      end

      #
      # Processes packets from a live capture or savefile until cnt packets 
      # are processed, the end of the savefile is reached (when reading
      # from a savefile), `pcap_breakloop()` is called, or an error occurs. 
      #
      # It does not return when live read timeouts occur. A value of -1 or
      # 0 for cnt is equivalent to infinity, so that packets are processed
      # until another ending condition occurs.
      #
      # (In older versions of libpcap, the behavior when cnt was 0 was
      # undefined; different platforms and devices behaved differently, so
      # code that must work with older versions of libpcap should use -1,
      # nor 0, as the value of cnt.)
      #
      # @param [Hash] opts
      #   Receive options.
      #
      # @option [optional, Integer] :count
      #   Limit to :count number of packets. Default is infinite.
      #
      # @yield [self, pkt] 
      #
      # @yieldparam [CaptureWrapper] self
      #   A reference to self is passed to the block.
      #
      # @yieldparam [Packet] pkt
      #   A packet object is yielded which references the header and bytes.
      #
      #
      # @return [Integer, nil]
      #   Returns 0 if cnt is exhausted, or `nil` if the loop terminated due
      #   to a call to `pcap_breakloop()` before any packets were processed.
      #   It does not return when live read timeouts occur; instead,
      #   it attempts to read more packets.
      #
      # @raise [ReadError]
      #   An exception is raised if an error occurs or if libpcap returns
      #   an unexpected value.
      #
      def loop(opts={}, &block)
        cnt = (opts[:count] || DEFAULT_COUNT)
        h = opts[:handler]

        ret = PCap.pcap_loop(_pcap, cnt, _wrap_callback(h, block), nil)

        if ret == -1
          raise(ReadError,"pcap_loop(): #{geterr}",caller)
        elsif ret -2
          return nil
        elsif ret > -1
          return ret
        else
          raise(ReadError,"unexpected return from pcap_loop(): #{ret}",caller)
        end
      end

      alias each loop

      #
      # Processes packets from a live capture or savefile until cnt packets
      # are processed, the end of the current bufferful of packets is
      # reached when doing a live capture, the end of the savefile is
      # reached (when reading from a savefile), `pcap_breakloop()` is called,
      # or an error occurs. 
      # 
      # Thus, when doing a live capture, cnt is the maximum number of
      # packets to process before returning, but is not a minimum number;
      # when reading a live capture, only one bufferful of packets is read
      # at a time, so fewer than cnt packets may be processed. A value of
      # -1 or 0 for cnt causes all the packets received in one buffer to be
      # processed when reading a live capture, and causes all the packets
      # in the file to be processed when reading a savefile.
      # 
      # Note: In older versions of libpcap, the behavior when cnt was 0 was
      # undefined; different platforms and devices behaved differently, so
      # code that must work with older versions of libpcap should use -1,
      # nor 0, as the value of cnt.
      # 
      # @yield [self, pkt] 
      #
      # @yieldparam [CaptureWrapper] self
      #   A reference to self is passed to the block.
      #
      # @yieldparam [Packet] pkt
      #   A packet object is yielded which references the header and bytes.
      #
      # @return [Integer, nil]
      #   Returns the number of packets processed on success; this can be 0
      #   if no packets were read from a live capture or if no more packets
      #   are available in a savefile. It returns `nil` if the loop
      #   terminated due to a call to {CommonWrapper#stop} before any
      #   packets were processed.
      #
      # @raise [ReadError]
      #   An exception is raised if an error occurs or if libpcap returns
      #   an unexpected value.
      #
      def dispatch(opts={}, &block)
        cnt = (opts[:count] || DEFAULT_COUNT) # default to infinite loop
        h = opts[:handler]

        ret = PCap.pcap_dispatch(_pcap, cnt, _wrap_callback(h, block),nil)

        if ret == -1
          raise(ReadError,"pcap_dispatch(): #{geterr}",caller)
        elsif ret -2
          return nil
        elsif ret > -1
          return ret
        else
          raise(ReadError,"unexpected return from pcap_dispatch() -> #{ret}",caller)
        end
      end

      #
      # This method uses the older `pcap_next()` function which has been
      # deprecated in favor of `pcap_next_ex()`. It is included only for
      # backward compatability purposes.
      #
      # Important Note. According to libpcap documentation: 
      #
      #     Unfortunately, there is no way to determine whether an error 
      #     occured or not when using pcap_next().
      #
      def old_next
        header = PacketHeader.new
        bytes = PCap.pcap_next(_pcap, header)

        return Packet.new(header, bytes) unless bytes.null?
      end

      #
      # Reads the next packet from a pcap device and returns a
      # success/failure indication.
      #
      # @return [Packet, nil]
      #   A packet is returned on success or a `nil` if the timeout expired
      #   or all packets in a dump file have been exhausted when reading
      #   from a savefile.
      #
      # @raise [ReadError]
      #   This exception is raised if there was an error calling
      #   `pcap_next_ex()`.
      #
      # @raise [TimeoutError]
      #   This exception is raised if the timeout expires
      #
      def next
        hdr_p = MemoryPointer.new(:pointer)
        buf_p = MemoryPointer.new(:pointer)

        case PCap.pcap_next_ex(_pcap, hdr_p, buf_p)
        when -1 # error
          raise(ReadError,"pcap_next_ex(): #{geterr}",caller)
        when 0  # live capture read timeout expired
          return nil
        when -2 # savefile packets exhausted
          return nil
        when 1
          hdr = PacketHeader.new(hdr_p.get_pointer(0))
          return Packet.new(hdr, buf_p.get_pointer(0))
        end
      end

      alias next_extra next
      alias next_ex next

      #
      # Sets a flag that will force {#dispatch} or {#loop} to return rather 
      # than looping; they will return the number of packets that have been 
      # processed so far, or `nil` if no packets have been processed so far.
      #
      # breakloop does not guarantee that no further packets will be
      # processed by {#dispatch} or {#loop} after it is called. At most
      # one more packet may be processed.
      #
      def breakloop
        PCap.pcap_breakloop(_pcap)
      end

      alias stop breakloop

      #
      # Used to specify a pcap filter for the pcap interface. This method 
      # compiles a filter expression and applies it on the wrapped pcap 
      # interface.
      #
      # @param [String] expression
      #   A pcap filter expression. See pcap-filter(7) manpage for syntax.
      #
      # @param [Hash] opts
      #   Compile options. See compile()
      #
      # @raise [LibError]
      #   On failure, an exception is raised with the relevant error
      #   message from libpcap.
      #
      def set_filter(expression, opts={})
        code = compile(expression, opts)
        ret = PCap.pcap_setfilter(_pcap, code)

        # done with this, we can free it
        code.free!

        if ret < 0
          raise(LibError, "pcap_setfilter(): #{geterr}",caller)
        end

        return expression
      end

      alias setfilter set_filter
      alias filter= set_filter

      def fileno
        PCap.pcap_fileno(_pcap)
      end

      def selectable_fd
        if PCap.respond_to?(:pcap_get_selectable_fd)
          PCap.pcap_get_selectable_fd(pcap)
        else
          raise(NotImplementedError, "selectable pcap IO is not available for your platform")
        end
      end

      def selectable_io
        ::IO.new(self.selectable_fd, 'r')
      end

      def _wrap_callback(h, block)
        h ||= @handler

        if h
          h = h.new() if h.kind_of?(Class)

          unless h.respond_to?(:receive_pcap)
            raise(NoMethodError, "The handler #{h.class} has no receive_pcap method",caller)
          end

          return lambda { |usr,phdr,body| 
            yld = h.receive_pcap(self, Packet.new(phdr,body))

            block.call(*yld) if (block && yld)
          }
        elsif (block.kind_of?(Proc) || block.kind_of?(Method))
          return lambda { |usr,phdr,body|
            block.call(pcap,Packet.new(phdr,body))
          }
        else
          raise(ArgumentError,"Neither a handler nor block were provided",caller)
        end
      end

      private :_wrap_callback

    end

    callback :pcap_handler, [:pointer, PacketHeader, :pointer], :void
    attach_function :pcap_loop, [:pcap_t, :int, :pcap_handler, :pointer], :int
    attach_function :pcap_dispatch, [:pcap_t, :int, :pcap_handler, :pointer], :int
    attach_function :pcap_next, [:pcap_t, PacketHeader], :pointer
    attach_function :pcap_next_ex, [:pcap_t, :pointer, :pointer], :int
    attach_function :pcap_breakloop, [:pcap_t], :void
    attach_function :pcap_setfilter, [:pcap_t, BPFProgram], :int
    attach_function :pcap_fileno, [:pcap_t], :int
  end
end
