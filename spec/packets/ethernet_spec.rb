require 'pcap_ffi/handler'
require 'pcap_ffi/packets/ethernet'

require 'spec_helper'
require 'helpers/dumps'

describe Packets::Ethernet do
  before(:all) do
    pcap = load_dump('http')
    header, raw = pcap.next

    @ether = raw.next
    pcap.close
  end

  before(:each) do
    @pcap = load_dump('http')
  end

  after(:each) do
    @pcap.close
  end

  it "should be a Packet" do
    Packets::Ethernet.include?(Packet).should == true
  end

  it "should wrap around a pcap raw packet" do
    lambda {
      @pcap.loop do |user,header,raw|
        ether = raw.next
      end
    }.should_not raise_error
  end

  it "should be exactly 14 bytes long" do
    @ether.size.should == 14
  end

  it "should have a source MAC address" do
    @ether.src_mac.should == [0x00, 0x23, 0x4e, 0x57, 0x7e, 0x51]
  end

  it "should have a destination MAC address" do
    @ether.dest_mac.should == [0x00, 0x16, 0x01, 0xed, 0x0d, 0x70]
  end

  it "should be able to determine payload type" do
    @ether.should be_ip
    @ether.should_not be_pup
  end

  it "should have an ethernet type" do
    @ether.type.should == Packets::Ethernet::IP_TYPE
  end

  it "should have a payload" do
    @ether.payload.should_not be_nil
    @ether.payload.should_not be_null
  end
end
