require 'spec_helper'

describe FFI::PCap do
  subject { described_class }

  it ".lib_version() should expose the libpcap version banner" do
    subject.lib_version.should_not be_nil
    subject.lib_version.should_not be_empty
  end

  it ".lib_version_number() should expose the libpcap version number only" do
    subject.lib_version_number.should =~ /^\d+\.\d+\.\d+$/
  end

  it ".lookupdev() should return a device default device" do
    dev = subject.lookupdev

    dev.should_not be_nil
    dev.should_not be_empty
  end

  it ".each_device() should enumerate over all usable interfaces" do
    i = 0

    subject.each_device do |dev|
      dev.should_not be_nil
      dev.should be_kind_of(Interface)

      [true,false].include?(dev.loopback?).should == true
      i+=1
    end
    i.should_not == 0
  end

  it ".device_names() should return names for all network interfaces" do
    devs = subject.device_names
    devs.should be_kind_of(Array)

    i = 0

    devs.each do |dev|
      dev.should     be_kind_of(String)
      dev.should_not be_empty

      i += 1
    end

    i.should_not == 0
    devs.include?(PCAP_DEV).should == true
  end

  it ".dump_devices() should return name/network pairs for all interfaces" do
    i = 0

    devs = subject.dump_devices
    devs.should be_kind_of(Array)

    devs.each do |(dev,net)|
      dev.should be_kind_of(String)
      dev.should_not be_empty

      i += 1
    end

    i.should_not == 0

    devs.select{|dev,net| not net.nil? }.should_not be_empty
    devs.map{|dev,net| dev}.include?(PCAP_DEV).should == true
  end

  it ".open_live() should open a live pcap handler given a chosen device" do
    lambda {
      pcap = subject.open_live(:device => PCAP_DEV)
      pcap.device.should == PCAP_DEV
      pcap.close
    }.should_not raise_error(Exception)
  end

  it ".open_live() should open a live pcap handler using a default device" do
    lambda {
      # XXX Using Vista and wpcap.dll this breaks on me.
      #     The lookupdev for a default adapter result is '\', which is just
      #     wrong.
      pcap = subject.open_live()
      pcap.should be_ready
      pcap.close
    }.should_not raise_error(Exception)
  end

  it ".open_dead() should open a dead pcap handler" do
    lambda {
      pcap = subject.open_dead()
      pcap.should be_ready
      pcap.close
    }.should_not raise_error(Exception)
  end

  it ".open_offline() should open a pcap dump file" do
    lambda {
      pcap = subject.open_offline(PCAP_TESTFILE)
      pcap.should be_ready
      pcap.close
    }.should_not raise_error(Exception)
  end

  it ".open_file() should work the same as .open_offline()" do
    lambda {
      pcap = subject.open_offline(PCAP_TESTFILE)
      pcap.should be_ready
      pcap.close
    }.should_not raise_error(Exception)
  end

  it ".open_live() should take a block and close the device after calling it" do
    pcap = nil

    ret = subject.open_live(:device => PCAP_DEV) do |this|
      this.should be_kind_of(Live)
      this.should be_ready
      this.should_not be_closed

      pcap = this
    end

    ret.should be_nil
    pcap.should_not be_ready
    pcap.should be_closed
  end

  it ".open_dead() should take a block and close the device after calling it" do
    pcap = nil

    ret = subject.open_dead() do |this|
      this.should be_kind_of(Dead)
      this.should be_ready
      this.should_not be_closed

      pcap = this
    end

    ret.should be_nil
    pcap.should_not be_ready
    ret.should be_nil
  end

  it ".open_file() should take a block and close the device after calling it" do
    pcap = nil

    ret = subject.open_file(PCAP_TESTFILE) do |this|
      this.should be_kind_of(Offline)
      this.should be_ready
      this.should_not be_closed

      pcap = this
    end

    ret.should be_nil
    pcap.should_not be_ready
    ret.should be_nil
  end
end
