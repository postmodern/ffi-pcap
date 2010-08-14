rubyforge_project = 'ffi-pcap'
name = "ffi-pcap"
summary = "FFI bindings for libpcap"
email = "postmodern.mod3@gmail.com"
homepage = "http://github.com/sophsec/ffi-pcap"
description = "Bindings to libpcap via FFI interface in Ruby."
authors = ["Postmodern", "Dakrone", "Eric Monti"]

### touch '.justrake' in the toplevel directory
### to use a pared down project rakefile
### with fewer development dependencies
unless File.exists?('.justrake')
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
    gem.rubyforge_project = rubyforge_project
    gem.name = name
    gem.summary = summary
    gem.email = email
    gem.homepage = homepage
    gem.description = description
    gem.authors = authors
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

else
  STDERR.puts "!! Using pared down Rake setup.",
              "!! For bundler/jeweler, rm the .justrake file at root"

  load 'tasks/setup.rb'

  ensure_in_path 'lib'

  task :default => 'spec:run'

  PROJ.name        = rubyforge_project
  PROJ.authors     = authors
  PROJ.email       = email
  PROJ.summary     = summary
  PROJ.description = description
  PROJ.url         = homepage

  PROJ.version     = File.open("VERSION","r"){|f| f.readline.chomp}
  PROJ.readme_file = 'README.md'
  PROJ.history_file = 'ChangeLog.md'

  PROJ.spec.opts += File.read(".specopts").split("\n")

  # exclude rcov.rb and external libs from rcov report
  PROJ.rcov.opts += [
    "--exclude",  "rcov", 
    "--exclude", "ffi",
    "--exclude", "ffi_dry",
  ]


  depend_on 'ffi', '>= 0.5.0'
  depend_on 'ffi_dry', '>= 0.1.9'

end


