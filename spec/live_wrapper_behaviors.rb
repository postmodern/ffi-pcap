require 'spec_helper'
require 'common_wrapper_examples'

shared_examples_for "PCap::LiveWrapper" do
  it_should_behave_like "PCap::CommonWrapper"

  it "should support non-blocking mode" do
    @pcap.non_blocking = true
    @pcap.should be_non_blocking
  end

  it "should provide statistics about packets received/dropped" do
    i == 0
    @pcap.loop {|*x| @pcap.stop if (i += 1) == 10 }
    i.should_not == 0
    stats = @pcap.stats
    stats.received.should > 0
    stats.received.should == 10
  end
end

