require 'pcap/mac_addr'

require 'spec_helper'

describe MACAddr do
  before(:all) do
    @mac = MACAddr.parse('ff:ff:c3:0d:25:e3')
  end

  it "should be exactly 6 bytes long" do
    @mac.size.should == 6
  end

  it "should parse MAC addresses" do
    @mac[0].should == 0xff
    @mac[1].should == 0xff
    @mac[2].should == 0xc3
    @mac[3].should == 0x0d
    @mac[4].should == 0x25
    @mac[5].should == 0xe3
  end

  it "should provide field access" do
    @mac[:bytes].should be_kind_of(FFI::Struct::Array)
  end

  it "should provide indexed byte access" do
    @mac[0] = 0xff

    @mac[0].should == 0xff
  end

  it "should be able to be compared with other MACs" do
    @mac.should == [0xff, 0xff, 0xc3, 0x0d, 0x25, 0xe3]
    @mac.should_not == [0xff, 0xff, 0x00, 0x0d, 0x00, 0xe3]
  end

  it "should be able to be converted to an Array" do
    @mac.to_a.should == [0xff, 0xff, 0xc3, 0x0d, 0x25, 0xe3]
  end

  it "should be able to be converted to a String" do
    @mac.to_s.should == 'ff:ff:c3:0d:25:e3'
  end
end
