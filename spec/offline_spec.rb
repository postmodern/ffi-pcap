require 'spec_helper'
require 'wrapper_behaviors'

describe Offline do
  before(:each) do
    @pcap = PCap.open_offline(PCAP_TESTFILE)
  end

  after(:each) do
    @pcap.close
  end

  it_should_behave_like "PCap::CaptureWrapper"

  it "should return a nil from next() at the end of the dump file" do
    i = 0
    @pcap.loop { i+=1 }
    i.should > 0
    @pcap.next.should be_nil
  end

  it "should supply a file version" do
    @pcap.file_version.should =~ /^\d+\.\d+$/
  end

  it "should indicate whether it is endian swapped" do
    [true,false].include?(@pcap.swapped?).should == true
  end

end

