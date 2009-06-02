require 'pcap_ffi/pcap'
require 'pcap_ffi/version'

require 'spec_helper'
require 'helpers/dumps'

describe PCap do
  it "should define a VERSION constant" do
    PCap.const_defined?('VERSION').should == true
  end

  it "should have a library version" do
    PCap.lib_version.should_not be_empty
  end

  it "should return the name of a device suitable for open_live" do
    dev = PCap.device

    dev.should_not be_nil
    dev.should_not be_empty
  end

  it "should enumerate over all usable devices" do
    PCap.each_device do |dev|
      dev.should_not be_nil
      dev.should_not be_null
      dev.class.should == PCap::IF
    end
  end

  it "should be able to open a live pcap handler" do
    lambda {
      pcap = PCap.open_live
      pcap.close
    }.should_not raise_error(StandardError)
  end

  it "should be able to open a dead pcap handler" do
    lambda {
      pcap = PCap.open_dead('null')
      pcap.close
    }.should_not raise_error(StandardError)
  end

  it "should be able to open a pcap dump file" do
    lambda {
      pcap = PCap.open_offline(dump_path('simple_tcp'))
      pcap.close
    }.should_not raise_error(StandardError)
  end
end
