require 'pcap/pcap'
require 'pcap/version'

require 'spec_helper'

describe PCap do
  it "should define a VERSION constant" do
    PCap.const_defined?('VERSION').should == true
  end
end
