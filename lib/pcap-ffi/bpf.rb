
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


  attach_function :pcap_compile_nopcap, [:int, :int, BPFProgram, :string, :int, :bpf_uint32], :int

  # Compiles a bpf filter without a pcap device being open. Downside is
  # no error messages are available, whereas they are when you use open_dead()
  # and use compile() on the resulting DeadWrapper.
  #
  # @options [Hash] opts
  #   Additional options for compile
  #
  # @option opts [optional, DataLink, Integer, String, Symbol] :datalink
  #   DataLink layer type. The argument type will be resolved to a DataLink
  #   value if possible. Defaults to data-link layer type NULL.
  #
  # @option opts [optional, Integer] :snaplen
  #   The snapshot length for the filter. Defaults to SNAPLEN
  #
  # @option opts [optional, Integer] :optimize
  #   Optimization flag. 0 means don't optimize. Defaults to 1.
  #
  # @option opts [optional, Integer] :netmask
  #   A 32-bit number representing the IPv4 netmask of the network on which
  #   packets are being captured. It is only used when checking for IPv4
  #   broadcast addresses in the filter program. Default: 0 (unspecified 
  #   netmask)
  #
  # @return [BPFProgram]
  #   If no errors occur, a compiled BPFProgram is returned.
  #
  def self.compile(expr, opts={})
    datalink = (opts[:datalink] || 0)
    dl = datalink.kind_of?(DataLink) ? datalink : DataLink.new(datalink)
    o = opts.merge(:snaplen => DEFAULT_SNAPLEN)

    optimize = (opts[:optimize] || 1)
    netmask  = (opts[:netmask] || 0)
    code = BPFProgram.new
    ret = PCap.pcap_compile_nopcap(dl.value, snaplen, code, expr, optimize, mask)
    raise(LibError, "pcap_compile_nopcap(): unspecified error") if ret < 0
    return code
  end

  attach_function :bpf_filter, [BPFInstruction, :pointer, :uint, :uint], :uint
  attach_function :bpf_validate, [BPFInstruction, :int], :int
  attach_function :bpf_image, [BPFInstruction, :int], :string
  attach_function :bpf_dump, [BPFProgram, :int], :void


end

