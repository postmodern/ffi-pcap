
module FFI::PCap

  # Includes structures defined in pcap-bpf.h

  # Berkeley Packet Filter instruction data structure.
  #
  # See bpf_insn struct in pcap-bpf.h
  class BPFInstruction < FFI::Struct
    include FFI::DRY::StructHelper

    dsl_layout do
      field :code,  :ushort
      field :jt,    :uchar
      field :jf,    :uchar
      field :k,     :bpf_int32
    end
  end

  # Structure for pcap_compile(), pcap_setfilter(), etc.
  #
  # See bpf_program struct in pcap-bpf.h
  class BPFProgram < FFI::Struct
    include FFI::DRY::StructHelper

    dsl_layout do
      field    :bf_len, :uint
      p_struct :bf_insn, BPFInstruction
    end
  end

end

