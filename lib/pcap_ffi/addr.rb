require 'pcap_ffi/typedefs'
require 'pcap_ffi/sock_addr'

require 'ffi/struct'

module FFI
  module PCap
    class Addr < FFI::Struct
      layout :next, :pointer,
             :addr, :pointer,
             :netmask, :pointer,
             :broadaddr, :pointer,
             :dstaddr, :pointer

      def next
        Addr.new(self[:next])
      end

      def addr
        SockAddr.new(self[:addr])
      end

      def netmask
        SockAddr.new(self[:netmask])
      end

      def broadcast
        SockAddr.new(self[:broadaddr])
      end

      def dest_addr
        SockAddr.new(self[:destaddr])
      end

    end
  end
end
