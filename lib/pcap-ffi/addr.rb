module FFI
  module PCap

    # Representation of an interface address.
    #
    # See pcap_addr struct in pcap.h
    class Addr < FFI::Struct
      include FFI::DRY::StructHelper

      dsl_layout do
        p_struct :next,       Addr
        p_struct :addr,       SockAddr, :desc => 'address'
        p_struct :netmask,    SockAddr, :desc => 'netmask of the address'
        p_struct :broadcast,  SockAddr, :desc => 'broadcast for the address'
        p_struct :dest_addr,  SockAddr, :desc => 'p2p destination for address'
      end

    end
  end
end
