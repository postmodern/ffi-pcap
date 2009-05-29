require 'pcap/handler'

require 'spec_helper'

shared_examples_for "Handler" do
  it "must have a datalink" do
    datalink = @pcap.datalink

    datalink.value.should_not be_nil
    datalink.name.should_not be_empty
  end

  it "should pass packets to a callback" do
    @pcap.callback do |user,pkthdr,bytes|
      hdr = PacketHeader.new(pkthdr)
      hdr.captured.should_not == 0
      hdr.length.should_not == 0

      bytes.should_not be_null
    end

    @pcap.loop
  end

  it "should be able to get the next packet" do
    header, data = @pcap.next

    header.should_not be_nil
    header.captured.should_not == 0
    header.length.should_not == 0

    data.should_not be_nil
    data.should_not be_null
  end

  it "should return an empty String when an error has not occurred" do
    @pcap.error.should be_empty
  end

  it "should be able to break out of the Handler#loop" do
    stopped = false

    @pcap.loop do |user,pkthdr,bytes|
      stopped = true
      @pcap.stop
    end

    stopped.should == true
  end
end
