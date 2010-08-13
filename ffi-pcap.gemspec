# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{ffi-pcap}
  s.version = "0.2.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Postmodern", "Dakrone", "Eric Monti"]
  s.date = %q{2010-08-13}
  s.description = %q{Bindings to libpcap via FFI interface in Ruby.}
  s.email = %q{postmodern_mod3@gmail.com}
  s.extra_rdoc_files = ["LICENSE.txt"]
  s.files = [".specopts", ".yardopts", "ChangeLog.md", "LICENSE.txt", "README.md", "Rakefile", "VERSION", "examples/ipfw_divert.rb", "examples/print_bytes.rb", "examples/selectable_pcap.rb", "ffi-pcap-0.2.1.gem", "lib/ffi-pcap.rb", "lib/ffi/pcap.rb", "lib/ffi/pcap/addr.rb", "lib/ffi/pcap/bpf_instruction.rb", "lib/ffi/pcap/bpf_program.rb", "lib/ffi/pcap/bsd.rb", "lib/ffi/pcap/bsd/af.rb", "lib/ffi/pcap/bsd/in6_addr.rb", "lib/ffi/pcap/bsd/in_addr.rb", "lib/ffi/pcap/bsd/sock_addr.rb", "lib/ffi/pcap/bsd/sock_addr_dl.rb", "lib/ffi/pcap/bsd/sock_addr_family.rb", "lib/ffi/pcap/bsd/sock_addr_in.rb", "lib/ffi/pcap/bsd/sock_addr_in6.rb", "lib/ffi/pcap/bsd/typedefs.rb", "lib/ffi/pcap/capture_wrapper.rb", "lib/ffi/pcap/common_wrapper.rb", "lib/ffi/pcap/copy_handler.rb", "lib/ffi/pcap/crt.rb", "lib/ffi/pcap/data_link.rb", "lib/ffi/pcap/dead.rb", "lib/ffi/pcap/dumper.rb", "lib/ffi/pcap/error_buffer.rb", "lib/ffi/pcap/exceptions.rb", "lib/ffi/pcap/file_header.rb", "lib/ffi/pcap/in_addr.rb", "lib/ffi/pcap/interface.rb", "lib/ffi/pcap/live.rb", "lib/ffi/pcap/offline.rb", "lib/ffi/pcap/packet.rb", "lib/ffi/pcap/packet_header.rb", "lib/ffi/pcap/pcap.rb", "lib/ffi/pcap/stat.rb", "lib/ffi/pcap/stat_ex.rb", "lib/ffi/pcap/time_val.rb", "lib/ffi/pcap/typedefs.rb", "spec/data_link_spec.rb", "spec/dead_spec.rb", "spec/dumps/http.pcap", "spec/dumps/simple_tcp.pcap", "spec/error_buffer_spec.rb", "spec/file_header_spec.rb", "spec/live_spec.rb", "spec/offline_spec.rb", "spec/packet_behaviors.rb", "spec/packet_injection_spec.rb", "spec/packet_spec.rb", "spec/pcap_spec.rb", "spec/spec_helper.rb", "spec/wrapper_behaviors.rb", "tasks/ann.rake", "tasks/doc.rake", "tasks/gem.rake", "tasks/git.rake", "tasks/post_load.rake", "tasks/rubyforge.rake", "tasks/setup.rb", "tasks/spec.rake", "tasks/svn.rake", "tasks/test.rake"]
  s.homepage = %q{http://github.com/sophsec/ffi-pcap}
  s.rdoc_options = ["--main", "README.rdoc"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.6}
  s.summary = %q{FFI bindings for libpcap}

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<ffi>, [">= 0.5.0"])
      s.add_runtime_dependency(%q<ffi_dry>, [">= 0.1.9"])
    else
      s.add_dependency(%q<ffi>, [">= 0.5.0"])
      s.add_dependency(%q<ffi_dry>, [">= 0.1.9"])
    end
  else
    s.add_dependency(%q<ffi>, [">= 0.5.0"])
    s.add_dependency(%q<ffi_dry>, [">= 0.1.9"])
  end
end
