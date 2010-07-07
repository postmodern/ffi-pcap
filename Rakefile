require 'rubygems'
require 'bundler'

begin
  Bundler.setup(:development, :doc)
rescue Bundler::BundlerError => e
  STDERR.puts e.message
  STDERR.puts "Run `bundle install` to install missing gems"
  exit e.status_code
end

require 'rake'
require 'rake/clean'
require 'jeweler'

Jeweler::Tasks.new do |gem|
  gem.rubyforge_project = 'ffi-pcap'
  gem.name = "ffi-pcap"
  gem.summary = "FFI bindings for libpcap"
  gem.email = "postmodern.mod3@gmail.com"
  gem.homepage = "http://github.com/sophsec/ffi-pcap"
  gem.description = "Bindings to libpcap via FFI interface in Ruby."
  gem.authors = ["Postmodern", "Dakrone", "Eric Monti"]
  gem.requirements = ['libpcap or winpcap (if on Windows)']
  gem.has_rdoc = 'yard'
end

require 'spec/rake/spectask'

desc "Run all specifications"
Spec::Rake::SpecTask.new(:spec) do |spec|
  spec.libs += ['lib', 'spec']
  spec.spec_opts = ['--options', '.specopts']
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
