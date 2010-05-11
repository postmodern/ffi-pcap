module FFI
  module PCap
    #
    # Used to represent an IPv6 address in a sock_addr_in6 structure
    #
    class In6Addr < ::FFI::Struct

      include ::FFI::DRY::StructHelper

      dsl_layout do
        array :s6_addr, [:uint8, 16], :desc => 'IPv6 address'
      end

    end
  end
end
