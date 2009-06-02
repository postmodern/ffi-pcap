# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{pcap-ffi}
  s.version = "0.0.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Postmodern, Dakrone"]
  s.date = %q{2009-06-02}
  s.description = %q{Bindings to sniff packets using the FFI interface in Ruby.}
  s.email = %q{postmodern.mod3@gmail.com}
  s.extra_rdoc_files = [
    "README.txt"
  ]
  s.files = [
    ".gitignore",
     "History.txt",
     "Manifest.txt",
     "README.txt",
     "Rakefile",
     "VERSION",
     "examples/print_bytes.rb",
     "lib/pcap_ffi.rb",
     "lib/pcap_ffi/addr.rb",
     "lib/pcap_ffi/data_link.rb",
     "lib/pcap_ffi/dumper.rb",
     "lib/pcap_ffi/error_buffer.rb",
     "lib/pcap_ffi/exceptions.rb",
     "lib/pcap_ffi/exceptions/read_error.rb",
     "lib/pcap_ffi/exceptions/unsupported_datalink.rb",
     "lib/pcap_ffi/extensions.rb",
     "lib/pcap_ffi/extensions/ffi.rb",
     "lib/pcap_ffi/extensions/ffi/exceptions.rb",
     "lib/pcap_ffi/extensions/ffi/exceptions/unknown_endianness.rb",
     "lib/pcap_ffi/extensions/ffi/struct.rb",
     "lib/pcap_ffi/extensions/ffi/struct/array.rb",
     "lib/pcap_ffi/extensions/ffi/types.rb",
     "lib/pcap_ffi/ffi.rb",
     "lib/pcap_ffi/file_header.rb",
     "lib/pcap_ffi/handler.rb",
     "lib/pcap_ffi/if.rb",
     "lib/pcap_ffi/in_addr.rb",
     "lib/pcap_ffi/mac_addr.rb",
     "lib/pcap_ffi/packet.rb",
     "lib/pcap_ffi/packet_header.rb",
     "lib/pcap_ffi/packets.rb",
     "lib/pcap_ffi/packets/ethernet.rb",
     "lib/pcap_ffi/packets/fddi.rb",
     "lib/pcap_ffi/packets/icmp.rb",
     "lib/pcap_ffi/packets/icmp/data.rb",
     "lib/pcap_ffi/packets/icmp/echo.rb",
     "lib/pcap_ffi/packets/icmp/frag.rb",
     "lib/pcap_ffi/packets/icmp/icmp.rb",
     "lib/pcap_ffi/packets/ieee_802_2.rb",
     "lib/pcap_ffi/packets/ieee_802_3.rb",
     "lib/pcap_ffi/packets/ip.rb",
     "lib/pcap_ffi/packets/raw.rb",
     "lib/pcap_ffi/packets/tcp.rb",
     "lib/pcap_ffi/packets/token_ring.rb",
     "lib/pcap_ffi/packets/typedefs.rb",
     "lib/pcap_ffi/pcap.rb",
     "lib/pcap_ffi/sock_addr.rb",
     "lib/pcap_ffi/sock_addr_in.rb",
     "lib/pcap_ffi/stat.rb",
     "lib/pcap_ffi/time_val.rb",
     "lib/pcap_ffi/typedefs.rb",
     "lib/pcap_ffi/version.rb",
     "pcap-ffi.gemspec",
     "spec/data_link_spec.rb",
     "spec/dumps/http.pcap",
     "spec/dumps/simple_tcp.pcap",
     "spec/error_buffer.rb",
     "spec/handler_examples.rb",
     "spec/handler_spec.rb",
     "spec/helpers/dumps.rb",
     "spec/mac_addr_spec.rb",
     "spec/packets/ethernet_spec.rb",
     "spec/pcap_spec.rb",
     "spec/spec_helper.rb",
     "tasks/spec.rb"
  ]
  s.has_rdoc = true
  s.homepage = %q{http://github.com/postmodern/pcap-ffi}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubyforge_project = %q{pcap-ffi}
  s.rubygems_version = %q{1.3.1}
  s.summary = %q{FFI bindings for libpcap}
  s.test_files = [
    "spec/pcap_spec.rb",
     "spec/mac_addr_spec.rb",
     "spec/data_link_spec.rb",
     "spec/packets/ethernet_spec.rb",
     "spec/error_buffer.rb",
     "spec/spec_helper.rb",
     "spec/handler_spec.rb",
     "spec/handler_examples.rb",
     "spec/helpers/dumps.rb",
     "examples/print_bytes.rb"
  ]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 2

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
