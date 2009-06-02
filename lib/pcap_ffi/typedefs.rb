require 'pcap_ffi/extensions/ffi/types'

module FFI
  alias_type :long, :time_t
  alias_type :long, :suseconds_t
  alias_type :ushort, :sa_family_t
  alias_type :uint16, :in_port_t
  alias_type :uint32, :in_addr_t
  alias_type :int, :bpf_int32
  alias_type :uint, :bpf_uint32
end
