require 'ffi/pcap/bsd/typedefs'

module FFI
  module PCap
    #
    # Used to represent a 32-bit IPv4 address in a sock_addr_in structure
    # 
    class InAddr < ::FFI::Struct

      include ::FFI::DRY::StructHelper

      dsl_layout do
        field :in_addr,  :in_addr_t, :desc => 'inet address'
      end

    end
  end
end
