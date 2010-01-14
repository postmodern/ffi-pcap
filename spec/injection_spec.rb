require 'spec_helper'

describe "packet injection" do
  before(:all) do
    @pcap = PCap.open_live :device => PCAP_DEV, 
                           :promisc => false,
                           :timeout => 100,
                           :snaplen => 8192
  end

  after(:all) do
    @pcap.close
  end

  it "should allow injection of a Strings using inject()" do
    test_data = "A" * 1024
    @pcap.inject(test_data).should == test_data.size
    p=@pcap.next()
    Packet.should === p
    p.body.should == test_data
  end

  it "should allow injection of a Packet using inject()" do
    test_data = "A" * 512
    @pcap.inject(Packet.from_string(test_data)).should == test_data.size
    p=@pcap.next()
    Packet.should === p
    p.body.should == test_data
  end

end

