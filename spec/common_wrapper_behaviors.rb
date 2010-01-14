require 'spec_helper'

shared_examples_for "FFI::PCap::CommonWrapper" do
  it "must have a datalink" do
    datalink = @pcap.datalink
    datalink.value.should_not be_nil
    datalink.value.should === Numeric
    datalink.name.should_not be_empty
  end

  it "should pass packets to a block using each()" do
    @pcap.each do |this, pkt, tag|
      this.should == @pcap
      pkt.header.should_not be_nil
      pkt.header.captured.should_not == 0
      pkt.header.length.should_not == 0
      pkt.body_ptr.should_not be_nil
      pkt.body_ptr.should_not be_null
      pkt.body.should_not be_nil
      pkt.body.should_not be_empty
      # tag is an arbitrary identifier. unused for now.
    end
  end

  it "should be able to get the next packet" do
    pkt = @pcap.next
    pkt.should_behave_like "Packet populated"
  end

  it "should be able to open a dump file" do
    lambda {
      dumper = @pcap.open_dump(Tempfile.new.path)
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

  it "should be able to break out of the Handler#loop" do
    stopped = false

    @pcap.loop do |this, pkt, tag|
      stopped = true
      this.stop
    end

    stopped.should == true
  end

  it "should prevent double closes" do
    @pcap.close
    @pcap.should be_closed

    lambda {
      @pcap.close
    }.should_not raise_error(Exception)
  end
end
