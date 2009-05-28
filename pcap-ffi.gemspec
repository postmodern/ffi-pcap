# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{pcap-ffi}
  s.version = "0.0.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Postmodern, Dakrone"]
  s.date = %q{2009-05-27}
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
     "lib/pcap.rb",
     "lib/pcap/addr.rb",
     "lib/pcap/data_link.rb",
     "lib/pcap/dumper.rb",
     "lib/pcap/error_buffer.rb",
     "lib/pcap/exceptions.rb",
     "lib/pcap/exceptions/read_error.rb",
     "lib/pcap/ffi.rb",
     "lib/pcap/file_header.rb",
     "lib/pcap/handler.rb",
     "lib/pcap/if.rb",
     "lib/pcap/in_addr.rb",
     "lib/pcap/packet_header.rb",
     "lib/pcap/packets.rb",
     "lib/pcap/packets/ethernet.rb",
     "lib/pcap/packets/ip.rb",
     "lib/pcap/packets/tcp.rb",
     "lib/pcap/packets/typedefs.rb",
     "lib/pcap/pcap.rb",
     "lib/pcap/sock_addr.rb",
     "lib/pcap/sock_addr_in.rb",
     "lib/pcap/stat.rb",
     "lib/pcap/time_val.rb",
     "lib/pcap/typedefs.rb",
     "lib/pcap/version.rb",
     "pcap-ffi.gemspec",
     "spec/data_link_spec.rb",
     "spec/dumps/simple_tcp.pcap",
     "spec/error_buffer.rb",
     "spec/handler_examples.rb",
     "spec/handler_spec.rb",
     "spec/helpers/dumps.rb",
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
     "spec/data_link_spec.rb",
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
