require 'ffi/pcap/bsd/typedefs'

module FFI
  module PCap
    #
    # IPv6 socket address
    #
    class SockAddrIn6 < SockAddrFamily

      dsl_layout do
        field :len,      :uint8,       :desc => 'length of structure(24)'
        field :family,   :sa_family_t, :desc => 'address family (AF_INET6)'
        field :port,     :in_port_t,   :desc => 'transport layer port'
        field :flowinfo, :uint32,      :desc => 'priority & flow label'
        struct :addr,    ::FFI::PCap::In6Addr,     :desc => 'IPv6 address'
      end

    end
  end
end
