require 'spec_helper'

describe PCap do
  it "should define a VERSION constant" do
    PCap.const_defined?('VERSION').should == true
  end

  it "should expose the libpcap version banner" do
    PCap.lib_version.should_not be_nil
    PCap.lib_version.should_not be_empty
  end

  it "should expose the libpcap version number" do
    PCap.lib_version_number.should_not be_nil
    PCap.lib_version_number.should_not be_empty
    PCap.lib_version_number.should =~ /^\d+\.\d+\.\d+$/
  end

  it "should return the name of a device suitable for open_live" do
    dev = PCap.lookupdev
    dev.should_not be_nil
    dev.should_not be_empty
  end

  it "should enumerate over all usable devices with each_device()" do
    i = 0
    PCap.each_device do |dev|
      dev.should_not be_nil
      [true,false].include?(dev.loopback?).should == true
      i+=1
    end
    i.should_not == 0
  end

  it "should return name/network pairs for all devices with dump_devices()" do
    i = 0
    dump = PCap.dump_devices
    Array.should === dump

    dump.each do |y|
      y.size.should == 2
      dev, net = y
      String.should === dev
      dev.should_not be_nil
      dev.should_not be_empty
      i+=1
    end
    i.should_not == 0

    dump.select{|dev,net| not net.nil? }.should_not be_empty

  end

  it "should return names for all devices with device_names()" do
    dump = PCap.device_names
    Array.should === dump

    i = 0
    dump.each do |dev|
      String.should === dev
      dev.should_not be_nil
      dev.should_not be_empty
      i+=1
    end
    i.should_not == 0
  end


  it "open_live() should open a live pcap handler given a chosen device" do
    lambda {
      pcap = PCap.open_live(:device => PCAP_DEV)
      pcap.device.should == PCAP_DEV
      pcap.close
    }.should_not raise_error(Exception)
  end


  it "open_live() should open a live pcap handler using a default device" do
    lambda {
      pcap = PCap.open_live()
      pcap.should be_ready
      pcap.close
    }.should_not raise_error(Exception)
  end

  it "open_dead() should open a dead pcap handler" do
    lambda {
      pcap = PCap.open_dead()
      pcap.should be_ready
      pcap.close
    }.should_not raise_error(Exception)
  end

  it "open_offline() should open a pcap dump file" do
    lambda {
      pcap = PCap.open_offline(PCAP_TESTFILE)
      pcap.should be_ready
      pcap.close
    }.should_not raise_error(Exception)
  end

  it "open_file() should work the same as open_offline()" do
    lambda {
      pcap = PCap.open_offline(PCAP_TESTFILE)
      pcap.should be_ready
      pcap.close
    }.should_not raise_error(Exception)
  end
end
