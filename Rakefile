require 'rubygems'
require 'rake/clean'

# Generate a gem using jeweler
begin
  require 'jeweler'
  Jeweler::Tasks.new do |gemspec|
    gemspec.rubyforge_project = 'ffi-pcap'
    gemspec.name = "ffi-pcap"
    gemspec.summary = "FFI bindings for libpcap"
    gemspec.email = "postmodern.mod3@gmail.com"
    gemspec.homepage = "http://github.com/sophsec/ffi-pcap"
    gemspec.description = "Bindings to libpcap via FFI interface in Ruby."
    gemspec.authors = ["Postmodern", "Dakrone", "Eric Monti"]
    gemspec.add_dependency "ffi", ">= 0.5.0"
    gemspec.add_dependency "ffi_dry", ">= 0.1.9"
    gemspec.has_rdoc = 'yard'
  end
  Jeweler::GemcutterTasks.new
rescue LoadError
  puts "Jeweler not available. Install it with: sudo gem install technicalpickles-jeweler -s http://gems.github.com"
end

require 'spec/rake/spectask'

desc "Run all specifications"
Spec::Rake::SpecTask.new(:spec) do |t|
  t.libs += ['lib', 'spec']
  t.spec_opts = ['--colour', '--format', 'specdoc']
end
task :default => :spec

require 'spec/rake/spectask'
Spec::Rake::SpecTask.new(:rcov) do |spec|
  spec.libs << 'lib' << 'spec'
  spec.pattern = 'spec/**/*_spec.rb'
  spec.rcov = true
end

require 'yard'
YARD::Rake::YardocTask.new
task :docs => :yard
