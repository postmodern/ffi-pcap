require 'pcap-ffi/typedefs'

require 'ffi/struct'

module FFI
  module PCap
    class FileHeader < FFI::Struct
      include FFI::DRY::StructHelper

      dsl_layout do
        field :magic,         :bpf_uint32
        field :version_major, :ushort
        field :version_minor, :ushort
        field :thiszone,      :bpf_int32
        field :sigfigs,       :bpf_uint32
        field :snaplen,       :bpf_uint32
        field :linktype,      :bpf_uint32
      end

    end
  end
end
