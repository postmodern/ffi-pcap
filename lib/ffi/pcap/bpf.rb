require 'ffi/pcap/bpf/instruction'
require 'ffi/pcap/bpf/program'

module FFI
  module Pcap

    attach_function :pcap_compile_nopcap, [:int, :int, BPFProgram, :string, :int, :bpf_uint32], :int

    attach_function :bpf_filter, [BPFInstruction, :pointer, :uint, :uint], :uint
    attach_function :bpf_validate, [BPFInstruction, :int], :int
    attach_function :bpf_image, [BPFInstruction, :int], :string
    attach_function :bpf_dump, [BPFProgram, :int], :void
    attach_function :pcap_freecode, [BPFProgram], :void

  end
end
