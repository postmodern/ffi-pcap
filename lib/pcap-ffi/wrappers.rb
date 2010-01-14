require 'pcap-ffi/wrappers/common_wrapper'
require 'pcap-ffi/wrappers/capture_wrapper'
require 'pcap-ffi/wrappers/dead_wrapper'
require 'pcap-ffi/wrappers/file_wrapper'
require 'pcap-ffi/wrappers/live_wrapper'

module FFI
  module PCap

    #### XXX not sure if we even want FILE io stuff yet (or ever).

    #attach_function :pcap_fopen_offline, [:FILE, :pointer], :pcap_t
    #attach_function :pcap_file, [:pcap_t], :FILE
    #attach_function :pcap_dump_fopen, [:pcap_t, :FILE], :pcap_dumper_t
    #attach_function :pcap_fileno, [:pcap_t], :int

  end
end
