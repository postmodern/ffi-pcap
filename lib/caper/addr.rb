module FFI
  module PCap

    # Representation of an interface address.
    #
    # See pcap_addr struct in pcap.h
    class Addr < FFI::Struct
      include FFI::DRY::StructHelper

      dsl_layout do
        p_struct :next,       ::FFI::PCap::Addr
        p_struct :addr,       ::FFI::PCap::SockAddr, :desc => 'address'
        p_struct :netmask,    ::FFI::PCap::SockAddr, :desc => 'netmask of the address'
        p_struct :broadcast,  ::FFI::PCap::SockAddr, :desc => 'broadcast for the address'
        p_struct :dest_addr,  ::FFI::PCap::SockAddr, :desc => 'p2p destination for address'
      end

    end
  end
end
