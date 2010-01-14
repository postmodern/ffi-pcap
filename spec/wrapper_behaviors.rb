require 'spec_helper'
require 'tempfile'
require 'packet_behaviors'

shared_examples_for "PCap::CommonWrapper" do
  it "must have a datalink" do
    datalink = @pcap.datalink
    datalink.value.should_not be_nil
    Numeric.should === datalink.value
    datalink.name.should_not be_empty
  end

  it "should be able to open a dump file" do
    lambda {
      dumper = @pcap.open_dump(Tempfile.new(rand(0xffff).to_s).path)
      dumper.close
    }.should_not raise_error(Exception)
  end

  it "should raise an exception when opening a bad dump file" do
    lambda {
      @pcap.open_dump(File.join('','obviously','not','there'))
    }.should raise_error(Exception)
  end

  it "should return an empty String when an error has not occurred" do
    @pcap.error.should be_empty
  end

  it "should prevent double closes" do
    @pcap.close
    @pcap.should be_closed

    lambda {
      @pcap.close
    }.should_not raise_error(Exception)
  end
end

shared_examples_for "PCap::CaptureWrapper" do
  it_should_behave_like "PCap::CommonWrapper"

  it "should pass packets to a block using loop()" do
    i = 0
    @pkt = nil
    @pcap.loop(:count => 2) do |this, pkt, tag|
      this.should == @pcap
      pkt.should_not be_nil
      # tag is an arbitrary identifier. unused for now.
      i+=1
    end
    i.should == 2
  end

  it "should be able to get the next packet" do
    pkt = @pcap.next
    pkt.should_not be_nil
  end

  it "should be able to break out of the Handler#loop" do
    stopped = false
    i = 0

    @pcap.loop(:count => 3) do |this, pkt, tag|
      stopped = true
      i+=1
      this.stop
    end

    i.should == 1
    stopped.should == true
  end

end


