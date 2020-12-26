require 'spec_helper'

describe FFI::PCap do
  subject { described_class }

  it ".lib_version() should expose the libpcap version banner" do
    expect(subject.lib_version).not_to be_nil
    expect(subject.lib_version).not_to be_empty
  end

  it ".lib_version_number() should expose the libpcap version number only" do
    expect(subject.lib_version_number).to match(/^\d+\.\d+\.\d+$/)
  end

  it ".lookupdev() should return a device default device" do
    dev = subject.lookupdev

    expect(dev).not_to be_nil
    expect(dev).not_to be_empty
  end

  it ".each_device() should enumerate over all usable interfaces" do
    i = 0

    subject.each_device do |dev|
      expect(dev).not_to be_nil
      expect(dev).to be_kind_of(Interface)

      expect([true,false].include?(dev.loopback?)).to eq(true)
      i+=1
    end
    expect(i).not_to eq(0)
  end

  it ".device_names() should return names for all network interfaces" do
    devs = subject.device_names
    expect(devs).to be_kind_of(Array)

    i = 0

    devs.each do |dev|
      expect(dev).to     be_kind_of(String)
      expect(dev).not_to be_empty

      i += 1
    end

    expect(i).not_to eq(0)
    expect(devs.include?(PCAP_DEV)).to eq(true)
  end

  it ".dump_devices() should return name/network pairs for all interfaces" do
    i = 0

    devs = subject.dump_devices
    expect(devs).to be_kind_of(Array)

    devs.each do |(dev,net)|
      expect(dev).to be_kind_of(String)
      expect(dev).not_to be_empty

      i += 1
    end

    expect(i).not_to eq(0)

    expect(devs.select{|dev,net| not net.nil? }).not_to be_empty
    expect(devs.map{|dev,net| dev}.include?(PCAP_DEV)).to eq(true)
  end

  it ".open_live() should open a live pcap handler given a chosen device" do
    expect {
      pcap = subject.open_live(:device => PCAP_DEV)
      expect(pcap.device).to eq(PCAP_DEV)
      pcap.close
    }.not_to raise_error
  end

  it ".open_live() should open a live pcap handler using a default device" do
    expect {
      # XXX Using Vista and wpcap.dll this breaks on me.
      #     The lookupdev for a default adapter result is '\', which is just
      #     wrong.
      pcap = subject.open_live()
      expect(pcap).to be_ready
      pcap.close
    }.not_to raise_error
  end

  it ".open_dead() should open a dead pcap handler" do
    expect {
      pcap = subject.open_dead()
      expect(pcap).to be_ready
      pcap.close
    }.not_to raise_error
  end

  it ".open_offline() should open a pcap dump file" do
    expect {
      pcap = subject.open_offline(PCAP_TESTFILE)
      expect(pcap).to be_ready
      pcap.close
    }.not_to raise_error
  end

  it ".open_file() should work the same as .open_offline()" do
    expect {
      pcap = subject.open_offline(PCAP_TESTFILE)
      expect(pcap).to be_ready
      pcap.close
    }.not_to raise_error
  end

  it ".open_live() should take a block and close the device after calling it" do
    pcap = nil

    ret = subject.open_live(:device => PCAP_DEV) do |this|
      expect(this).to be_kind_of(Live)
      expect(this).to be_ready
      expect(this).not_to be_closed

      pcap = this
    end

    expect(ret).to be_nil
    expect(pcap).not_to be_ready
    expect(pcap).to be_closed
  end

  it ".open_dead() should take a block and close the device after calling it" do
    pcap = nil

    ret = subject.open_dead() do |this|
      expect(this).to be_kind_of(Dead)
      expect(this).to be_ready
      expect(this).not_to be_closed

      pcap = this
    end

    expect(ret).to be_nil
    expect(pcap).not_to be_ready
    expect(ret).to be_nil
  end

  it ".open_file() should take a block and close the device after calling it" do
    pcap = nil

    ret = subject.open_file(PCAP_TESTFILE) do |this|
      expect(this).to be_kind_of(Offline)
      expect(this).to be_ready
      expect(this).not_to be_closed

      pcap = this
    end

    expect(ret).to be_nil
    expect(pcap).not_to be_ready
    expect(ret).to be_nil
  end
end
