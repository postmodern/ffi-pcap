require 'pcap_ffi/error_buffer'

require 'spec_helper'

describe PCap::ErrorBuffer do
  before(:all) do
    @errbuf = PCap::ErrorBuffer.new
  end

  it "should have a size of 256" do
    @errbuf.size.should == 256
  end

  it "should return the error message for to_s" do
    @errbuf.write_string('test')
    @errbuf.to_s.should == 'test'
  end
end
