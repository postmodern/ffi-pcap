require 'ffi/pcap/bsd/af'

module FFI
  module PCap
    #
    # Common abstract superclass for all sockaddr struct classes
    #
    class SockAddrFamily < ::FFI::Struct

      include ::FFI::DRY::StructHelper

      # returns an address family name for the :family struct member value
      def lookup_family
        AF[self[:family]]
      end

    end
  end
end
