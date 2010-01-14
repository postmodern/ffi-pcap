require 'spec_helper'

describe PCap do
  it "should define a VERSION constant" do
    PCap.const_defined?('VERSION').should == true
  end

  it "should have a library version" do
    PCap.lib_version.should_not be_empty
  end

  it "should have a library version number" do
    PCap.lib_version_number.should_not be_empty
    PCap.lib_version_number.should =~ /^\d+\.\d+\.\d+$/
  end

  it "should return the name of a device suitable for open_live" do
    dev = PCap.lookupdev

    dev.should_not be_nil
    dev.should_not be_empty
  end

  it "should enumerate over all usable devices" do
    i = 0
    PCap.each_device do |dev|
      dev.should_not be_nil
      i+=1
    end
    i.should_not == 0
  end

  it "should be able to open a live pcap handler using a chosen device" do
    lambda {
      pcap = PCap.open_live(:device => PCAP_DEV)
      pcap.device.should == PCAP_DEV
      pcap.close
    }.should_not raise_error(StandardError)
  end


  it "should be able to open a live pcap handler using a default device" do
    lambda {
      pcap = PCap.open_live()
      pcap.close
    }.should_not raise_error(StandardError)
  end

  it "should be able to open a dead pcap handler" do
    lambda {
      pcap = PCap.open_dead()
      pcap.close
    }.should_not raise_error(StandardError)
  end

  it "should be able to open a pcap dump file" do
    lambda {
      pcap = PCap.open_offline(PCAP_TESTFILE)
      pcap.close
    }.should_not raise_error(StandardError)
  end
end
