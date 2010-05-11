require 'ffi/pcap/bsd/typedefs'
require 'ffi/pcap/bsd/sock_addr_family'

module FFI
  module PCap
    #
    # sockaddr inet, always good to have around
    #
    class SockAddrIn < SockAddrFamily

      dsl_layout do
        field :len,    :uint8,        :desc => 'length of structure (16)'
        field :family, :sa_family_t,  :desc => 'address family (AF_INET)'
        field :port,   :in_port_t,    :desc => '16-bit TCP or UDP port number'
        field :addr,   :in_addr_t,    :desc => '32-bit IPv4 address'
        array :_sa_zero, [:uint8,8],  :desc => 'unused'
      end

    end
  end
end
