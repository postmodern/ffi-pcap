require 'pcap/error_buffer'

require 'spec_helper'

describe PCap::ErrorBuffer do
  before(:all) do
    @errbuf = PCap::ErrorBuffer.new
  end

  it "should have a size of 256" do
    @errbuf.size.should == 256
  end
end
