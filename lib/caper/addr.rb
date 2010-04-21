
module Caper

  # Representation of an interface address.
  #
  # See pcap_addr struct in pcap.h
  class Addr < FFI::Struct
    include FFI::DRY::StructHelper

    dsl_layout do
      p_struct :next,       ::Caper::Addr
      p_struct :addr,       ::Caper::SockAddr, :desc => 'address'
      p_struct :netmask,    ::Caper::SockAddr, :desc => 'netmask of the address'
      p_struct :broadcast,  ::Caper::SockAddr, :desc => 'broadcast for the address'
      p_struct :dest_addr,  ::Caper::SockAddr, :desc => 'p2p destination for address'
    end

  end
end
