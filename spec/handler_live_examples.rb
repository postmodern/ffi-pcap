require 'pcap_ffi/handler'

require 'spec_helper'

shared_examples_for "Handler live" do
  it "should support non-blocking mode" do
    @pcap.non_blocking = true
    @pcap.should be_non_blocking
  end

  it "should provide statistics about packets received/dropped" do
    @pcap.loop

    stats = @pcap.stats
    stats.received.should > 0
  end
end
