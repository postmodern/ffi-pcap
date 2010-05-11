require 'ffi/pcap/bsd/af'
require 'ffi/pcap/bsd/in_addr'
require 'ffi/pcap/bsd/sock_addr'
require 'ffi/pcap/bsd/sock_addr_family'
require 'ffi/pcap/bsd/sock_addr_in'
require 'ffi/pcap/bsd/sock_addr_dl'
require 'ffi/pcap/bsd/in6_addr'
require 'ffi/pcap/bsd/sock_addr_in6'

module FFI
  module PCap
    typedef :uint8, :sa_family_t
    typedef :uint32, :in_addr_t
    typedef :uint16, :in_port_t
  end
end
