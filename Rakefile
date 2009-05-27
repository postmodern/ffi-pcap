# -*- ruby -*-

require 'rubygems'
require 'hoe'
require './lib/pcap/version.rb'
require './tasks/spec.rb'

Hoe.new('pcap-ffi', FFI::PCap::VERSION) do |p|
  p.rubyforge_name = 'pcap-ffi'
  p.developer('Postmodern','postmodern.mod3@gmail.com')
  p.remote_rdoc_dir = ''
  p.extra_deps = [['ffi', '>=0.4.0']]
end

# vim: syntax=Ruby
