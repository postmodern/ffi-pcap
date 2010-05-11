require 'ffi/pcap/bsd/typedefs'
require 'ffi/pcap/bsd/sock_addr_family'

module FFI
  module PCap
    #
    # generic sockaddr, always good to have around
    #
    class SockAddr < SockAddrFamily

      dsl_layout do
        field :len,    :uint8,        :desc => 'total length of struct'
        field :family, :sa_family_t,  :desc => 'address family (AF_*)'
        field :data,   :char,         :desc => 'variable length bound by :len'
      end

    end
  end
end
