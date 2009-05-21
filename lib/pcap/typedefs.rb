require 'ffi'

module FFI
  def self.alias_type(type,aliased)
    add_typedef(find_type(type),aliased.to_sym)
  end

  alias_type :long, :time_t
  alias_type :long, :suseconds_t
  alias_type :ushort, :sa_family_t
  alias_type :int, :bpf_int32
  alias_type :uint, :bpf_uint32
  alias_type :int, :pcap_direction_t
end
