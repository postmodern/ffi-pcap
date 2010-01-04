# Here's where various BSD sockets typedefs and structures go
# ... good to have around
# cribbed from dnet-ffi - EM

require 'socket'

module FFI::PCap
  typedef :uint8, :sa_family_t
  typedef :uint32, :in_addr_t
  typedef :uint16, :in_port_t

  # contains AF_* constants culled from Ruby's ::Socket
  module AF
    include ::FFI::DRY::ConstMap
    slurp_constants(::Socket, "AF_")
    def self.list; @@list ||= super() ; end
  end

  # Common abstract superclass for all sockaddr struct classes
  #
  class SockAddrFamily < ::FFI::Struct
    include ::FFI::DRY::StructHelper
    
    # returns an address family name for the :family struct member value
    def lookup_family
      AF[ self[:family] ]
    end
  end

  # generic sockaddr, always good to have around
  #
  class SockAddr < SockAddrFamily
    dsl_layout do
      field :len,    :uint8,        :desc => 'total length of struct'
      field :family, :sa_family_t,  :desc => 'address family (AF_*)'
      field :data,   :char,         :desc => 'variable length bound by :len'
    end
  end


  # Used to represent a 32-bit IPv4 address in a sock_addr_in structure
  # 
  class InAddr < ::FFI::Struct
    include ::FFI::DRY::StructHelper
    dsl_layout { field :in_addr,  :in_addr_t, :desc => 'inet address' }
  end

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

  # Used to represent an IPv6 address in a sock_addr_in6 structure
  #
  class In6Addr < ::FFI::Struct
    include ::FFI::DRY::StructHelper
    dsl_layout { array :s6_addr, [:uint8, 16], :desc => 'IPv6 address' }
  end

  # IPv6 socket address
  #
  class SockAddrIn6 < SockAddrFamily
    dsl_layout do
      field :len,      :uint8,       :desc => 'length of structure(24)'
      field :family,   :sa_family_t, :desc => 'address family (AF_INET6)'
      field :port,     :in_port_t,   :desc => 'transport layer port'
      field :flowinfo, :uint32,      :desc => 'priority & flow label'
      struct :addr,     In6Addr,     :desc => 'IPv6 address'
    end
  end


  # data-link socket address
  #
  class SockAddrDl < SockAddrFamily
    dsl_layout do
      field :len,       :uint8,   :desc => 'length of structure(variable)'
      field :family, :sa_family_t, :desc => 'address family (AF_LINK)'
      field :sdl_index, :uint16,  :desc => 'system assigned index, if > 0'
      field :dltype,    :uint8,   :desc => 'IFT_ETHER, etc. from net/if_types.h'
      field :nlen,      :uint8,   :desc => 'name length, from :_data'
      field :alen,      :uint8,   :desc => 'link-layer addres-length'
      field :slen,      :uint8,   :desc => 'link-layer selector length'
      field :_data,     :char,    :desc => 'minimum work area=12, can be larger'
    end
  end

end
