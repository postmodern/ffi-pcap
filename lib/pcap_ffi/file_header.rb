require 'pcap_ffi/typedefs'

require 'ffi/struct'

module FFI
  module PCap
    class FileHeader < FFI::Struct
      layout :magic, :bpf_uint32,
             :version_major, :ushort,
             :version_minor, :ushort,
             :thiszone, :bpf_int32,
             :sigfigs, :bpf_uint32,
             :snaplen, :bpf_uint32,
             :linktype, :bpf_uint32
    end
  end
end
