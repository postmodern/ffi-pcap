# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run the gemspec command
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{ffi-pcap}
  s.version = "0.1.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Postmodern"]
  s.date = %q{2010-02-11}
  s.description = %q{Ruby FFI bindings for libpcap.}
  s.email = %q{postmodern.mod3@gmail.com}
  s.extra_rdoc_files = [
    "ChangeLog.rdoc",
    "LICENSE.txt",
    "README.rdoc"
  ]
  s.files = [
    ".gitignore",
    ".specopts",
    ".yardopts",
    "ChangeLog.rdoc",
    "LICENSE.txt",
    "README.rdoc",
    "Rakefile",
    "examples/print_bytes.rb",
    "lib/pcap-ffi.rb",
    "lib/pcap-ffi/addr.rb",
    "lib/pcap-ffi/data_link.rb",
    "lib/pcap-ffi/dumper.rb",
    "lib/pcap-ffi/error_buffer.rb",
    "lib/pcap-ffi/exceptions.rb",
    "lib/pcap-ffi/exceptions/read_error.rb",
    "lib/pcap-ffi/exceptions/unsupported_datalink.rb",
    "lib/pcap-ffi/extensions.rb",
    "lib/pcap-ffi/extensions/ffi.rb",
    "lib/pcap-ffi/extensions/ffi/exceptions.rb",
    "lib/pcap-ffi/extensions/ffi/exceptions/unknown_endianness.rb",
    "lib/pcap-ffi/extensions/ffi/struct.rb",
    "lib/pcap-ffi/extensions/ffi/struct/array.rb",
    "lib/pcap-ffi/extensions/ffi/types.rb",
    "lib/pcap-ffi/ffi.rb",
    "lib/pcap-ffi/file_header.rb",
    "lib/pcap-ffi/handler.rb",
    "lib/pcap-ffi/if.rb",
    "lib/pcap-ffi/in_addr.rb",
    "lib/pcap-ffi/mac_addr.rb",
    "lib/pcap-ffi/packet.rb",
    "lib/pcap-ffi/packet_header.rb",
    "lib/pcap-ffi/packets.rb",
    "lib/pcap-ffi/packets/arp.rb",
    "lib/pcap-ffi/packets/ethernet.rb",
    "lib/pcap-ffi/packets/fddi.rb",
    "lib/pcap-ffi/packets/icmp.rb",
    "lib/pcap-ffi/packets/icmp/data.rb",
    "lib/pcap-ffi/packets/icmp/echo.rb",
    "lib/pcap-ffi/packets/icmp/frag.rb",
    "lib/pcap-ffi/packets/icmp/icmp.rb",
    "lib/pcap-ffi/packets/ieee_802_2.rb",
    "lib/pcap-ffi/packets/ieee_802_3.rb",
    "lib/pcap-ffi/packets/ip.rb",
    "lib/pcap-ffi/packets/raw.rb",
    "lib/pcap-ffi/packets/tcp.rb",
    "lib/pcap-ffi/packets/token_ring.rb",
    "lib/pcap-ffi/packets/typedefs.rb",
    "lib/pcap-ffi/pcap.rb",
    "lib/pcap-ffi/sock_addr.rb",
    "lib/pcap-ffi/sock_addr_in.rb",
    "lib/pcap-ffi/stat.rb",
    "lib/pcap-ffi/time_val.rb",
    "lib/pcap-ffi/typedefs.rb",
    "lib/pcap-ffi/version.rb",
    "spec/data_link_spec.rb",
    "spec/dumps/http.pcap",
    "spec/dumps/simple_tcp.pcap",
    "spec/error_buffer.rb",
    "spec/handler_examples.rb",
    "spec/handler_live_examples.rb",
    "spec/handler_spec.rb",
    "spec/helpers/dumps.rb",
    "spec/mac_addr_spec.rb",
    "spec/packets/ethernet_spec.rb",
    "spec/pcap_spec.rb",
    "spec/spec_helper.rb",
    "tasks/spec.rb",
    "tasks/yard.rb"
  ]
  s.has_rdoc = %q{yard}
  s.homepage = %q{http://github.com/sophsec/ffi-pcap}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.5}
  s.summary = %q{Ruby FFI bindings for libpcap.}
  s.test_files = [
    "spec/spec_helper.rb",
    "spec/pcap_spec.rb",
    "spec/error_buffer.rb",
    "spec/helpers/dumps.rb",
    "spec/handler_spec.rb",
    "spec/data_link_spec.rb",
    "spec/handler_examples.rb",
    "spec/mac_addr_spec.rb",
    "spec/packets/ethernet_spec.rb",
    "spec/handler_live_examples.rb",
    "examples/print_bytes.rb"
  ]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<ffi>, [">= 0.5.3"])
      s.add_development_dependency(%q<rspec>, [">= 1.3.0"])
      s.add_development_dependency(%q<yard>, [">= 0.5.3"])
    else
      s.add_dependency(%q<ffi>, [">= 0.5.3"])
      s.add_dependency(%q<rspec>, [">= 1.3.0"])
      s.add_dependency(%q<yard>, [">= 0.5.3"])
    end
  else
    s.add_dependency(%q<ffi>, [">= 0.5.3"])
    s.add_dependency(%q<rspec>, [">= 1.3.0"])
    s.add_dependency(%q<yard>, [">= 0.5.3"])
  end
end

