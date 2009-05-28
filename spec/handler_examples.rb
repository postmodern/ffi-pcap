require 'pcap/handler'

require 'spec_helper'

shared_examples_for "Handler" do
  it "should pass packets to a callback" do
    @pcap.callback do |user,pkthdr,bytes|
      hdr = PacketHeader.new(pkthdr)
      hdr.captured.should_not == 0
      hdr.length.should_not == 0

      bytes.should_not be_null
    end

    @pcap.loop
  end
end
