require 'pcap/pcap'
require 'pcap/version'

require 'spec_helper'

describe PCap do
  it "should define a VERSION constant" do
    PCap.const_defined?('VERSION').should == true
  end

  it "should return the name of a device suitable for open_live" do
    dev = PCap.device

    dev.should_not be_nil
    dev.should_not be_empty
  end

  it "should enumerate over all usable devices" do
    PCap.each_device do |dev|
      dev.should_not be_null
      dev.class.should == PCap::IF
    end
  end
end
