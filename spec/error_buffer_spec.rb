require 'spec_helper'

describe ErrorBuffer do
  before(:all) do
    @errbuf = ErrorBuffer.create
  end

  it "should have a size of 256" do
    @errbuf.size.should == 256
  end

  it "should return an error message with to_s" do
    @errbuf.to_s.should be_empty
    Caper.pcap_open_offline("/this/file/wont/exist/#{rand(0xFFFF)}", @errbuf )
    @errbuf.to_s.should_not be_empty
  end
end
