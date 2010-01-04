require 'pcap-ffi/typedefs'
require 'pcap-ffi/sock_addr'

require 'ffi/struct'

module FFI
  module PCap
    class Addr < FFI::Struct
      include FFI::DRY::StructHelper

      dsl_layout do
        p_struct :next,       Addr
        p_struct :addr,       SockAddr
        p_struct :netmask,    SockAddr
        p_struct :broadcast,  SockAddr
        p_struct :dest_addr,  SockAddr
      end

    end
  end
end
