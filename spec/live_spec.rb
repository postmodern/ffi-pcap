require 'spec_helper'
require 'wrapper_behaviors'

describe Live do
  before(:each) do
    @pcap = PCap.open_live(
      :device => PCAP_DEV,
      :promisc => true
    )
  end

  after(:each) do
    @pcap.close
  end

  it_should_behave_like "PCap::CaptureWrapper"

  it "should support non-blocking mode" do
    @pcap.non_blocking = true
    @pcap.should be_non_blocking
  end

  it "should provide statistics about packets received/dropped" do
    i = 0
    @pcap.loop {|*x| @pcap.stop if (i += 1) == 10 }
    i.should_not == 0
    stats = @pcap.stats
    stats.received.should > 0
    stats.received.should == 10
  end

end


