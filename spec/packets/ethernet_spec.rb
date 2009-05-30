require 'pcap'
require 'pcap/packets/ethernet'

require 'spec_helper'
require 'helpers/dumps'

describe Packets::Ethernet do
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
      @pcap.loop do |user,header,bytes|
        ether = Packets::Ethernet.new(bytes)
      end
    }.should_not raise_error
  end

  it "should be exactly 14 bytes long" do
    header, bytes = @pcap.next
    ether = Packets::Ethernet.new(bytes)

    ether.size.should == 14
  end

  it "should have a source MAC address" do
    header, bytes = @pcap.next
    ether = Packets::Ethernet.new(bytes)

    ether.src_mac.should == [0x00, 0x23, 0x4e, 0x57, 0x7e, 0x51]
  end

  it "should have a destination MAC address" do
    header, bytes = @pcap.next
    ether = Packets::Ethernet.new(bytes)

    ether.dest_mac.should == [0x00, 0x16, 0x01, 0xed, 0x0d, 0x70]
  end

  it "should have an ethernet type" do
    header, bytes = @pcap.next
    ether = Packets::Ethernet.new(bytes)

    ether.type.should == Packets::Ethernet::IP_TYPE
  end

  it "should be able to determine payload type" do
    header, bytes = @pcap.next
    ether = Packets::Ethernet.new(bytes)

    ether.should be_ip
    ether.should_not be_pup
  end

  it "should have a payload" do
    header, bytes = @pcap.next
    ether = Packets::Ethernet.new(bytes)

    ether.payload.should_not be_nil
    ether.payload.should_not be_null
  end
end
