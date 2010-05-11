require 'ffi/pcap/bsd/typedefs'
require 'ffi/pcap/bsd/sock_addr_family'

module FFI
  module PCap
    #
    # data-link socket address
    #
    class SockAddrDl < SockAddrFamily

      dsl_layout do
        field :len,       :uint8,   :desc => 'length of structure(variable)'
        field :family,    :sa_family_t, :desc => 'address family (AF_LINK)'
        field :sdl_index, :uint16,  :desc => 'system assigned index, if > 0'
        field :dltype,    :uint8,   :desc => 'IFT_ETHER, etc. from net/if_types.h'
        field :nlen,      :uint8,   :desc => 'name length, from :_data'
        field :alen,      :uint8,   :desc => 'link-layer addres-length'
        field :slen,      :uint8,   :desc => 'link-layer selector length'
        field :_data,     :char,    :desc => 'minimum work area=12, can be larger'
      end

    end
  end
end
