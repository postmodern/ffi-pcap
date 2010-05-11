require 'spec_helper'

describe FFI::PCap do
  it ".lib_version() should expose the libpcap version banner" do
    FFI::PCap.lib_version.should_not be_nil
    FFI::PCap.lib_version.should_not be_empty
  end

  it ".lib_version_number() should expose the libpcap version number only" do
    FFI::PCap.lib_version_number.should_not be_nil
    FFI::PCap.lib_version_number.should_not be_empty
    FFI::PCap.lib_version_number.should =~ /^\d+\.\d+\.\d+$/
  end

  it ".lookupdev() should return a device deafult device" do
    dev = FFI::PCap.lookupdev
    dev.should_not be_nil
    dev.should_not be_empty
  end

  it ".each_device() should enumerate over all usable interfaces" do
    i = 0
    FFI::PCap.each_device do |dev|
      dev.should_not be_nil
      Interface.should === dev
      [true,false].include?(dev.loopback?).should == true
      i+=1
    end
    i.should_not == 0
  end

  it ".device_names() should return names for all network interfaces" do
    devs = FFI::PCap.device_names
    Array.should === devs
    i = 0
    devs.each do |dev|
      String.should === dev
      dev.should_not be_nil
      dev.should_not be_empty
      i+=1
    end
    i.should_not == 0
    devs.include?(PCAP_DEV).should == true
  end

  it ".dump_devices() should return name/network pairs for all interfaces" do
    i = 0
    devs = FFI::PCap.dump_devices
    Array.should === devs
    devs.each do |y|
      y.size.should == 2
      dev, net = y
      String.should === dev
      dev.should_not be_nil
      dev.should_not be_empty
      i+=1
    end
    i.should_not == 0
    devs.select{|dev,net| not net.nil? }.should_not be_empty
    devs.map{|dev,net| dev}.include?(PCAP_DEV).should == true
  end

  it ".open_live() should open a live pcap handler given a chosen device" do
    lambda {
      pcap = FFI::PCap.open_live(:device => PCAP_DEV)
      pcap.device.should == PCAP_DEV
      pcap.close
    }.should_not raise_error(Exception)
  end

  it ".open_live() should open a live pcap handler using a default device" do
    lambda {
      # XXX Using Vista and wpcap.dll this breaks on me.
      #     The lookupdev for a default adapter result is '\', which is just
      #     wrong.
      pcap = FFI::PCap.open_live()
      pcap.should be_ready
      pcap.close
    }.should_not raise_error(Exception)
  end

  it ".open_dead() should open a dead pcap handler" do
    lambda {
      pcap = FFI::PCap.open_dead()
      pcap.should be_ready
      pcap.close
    }.should_not raise_error(Exception)
  end

  it ".open_offline() should open a pcap dump file" do
    lambda {
      pcap = FFI::PCap.open_offline(PCAP_TESTFILE)
      pcap.should be_ready
      pcap.close
    }.should_not raise_error(Exception)
  end

  it ".open_file() should work the same as .open_offline()" do
    lambda {
      pcap = FFI::PCap.open_offline(PCAP_TESTFILE)
      pcap.should be_ready
      pcap.close
    }.should_not raise_error(Exception)
  end

  it ".open_live() should take a block and close the device after calling it" do
    pcap = nil
    ret = FFI::PCap.open_live(:device => PCAP_DEV) {|this|
      Live.should === this
      this.should be_ready
      this.should_not be_closed
      pcap = this
    }
    ret.should be_nil
    pcap.should_not be_ready
    pcap.should be_closed
  end

  it ".open_dead() should take a block and close the device after calling it" do
    pcap = nil
    ret = FFI::PCap.open_dead() {|this|
      Dead.should === this
      this.should be_ready
      this.should_not be_closed
      pcap = this
    }
    ret.should be_nil
    pcap.should_not be_ready
    ret.should be_nil
  end

  it ".open_file() should take a block and close the device after calling it" do
    pcap = nil
    ret = FFI::PCap.open_file(PCAP_TESTFILE) {|this|
      Offline.should === this
      this.should be_ready
      this.should_not be_closed
      pcap = this
    }
    ret.should be_nil
    pcap.should_not be_ready
    ret.should be_nil
  end

end
