require 'pcap_ffi/typedefs'
require 'pcap_ffi/in_addr'

require 'ffi'

module FFI
  module PCap
    class SockAddrIn < FFI::Struct

      layout :sin_family, :sa_family_t,
             :sin_port, :in_port_t,
             :sin_addr, InAddr,
             :sin_zero, [:char, ]

      def family
        self[:sin_family]
      end

      def addr
        InAddr.new(self[:sin_addr])
      end

    end
  end
end
