require 'ffi/pcap/typedefs'

module FFI
  module PCap
    #
    # Includes structures defined in `pcap-bpf.h`
    #
    # Berkeley Packet Filter instruction data structure.
    #
    # See bpf_insn struct in `pcap-bpf.h`
    #
    class BPFInstruction < FFI::Struct

      include FFI::DRY::StructHelper

      dsl_layout do
        field :code,  :ushort
        field :jt,    :uchar
        field :jf,    :uchar
        field :k,     :bpf_int32
      end

    end
  end
end
