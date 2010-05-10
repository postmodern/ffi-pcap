require 'spec_helper'
require 'tempfile'

shared_examples_for "FFI::PCap::CommonWrapper" do
  it "should indicate readiness" do
    @pcap.ready?.should == true
  end

  it "should have a datalink" do
    datalink = @pcap.datalink
    datalink.value.should_not be_nil
    Numeric.should === datalink.value
    datalink.name.should_not be_empty
  end

  it "should be able to open a dump file" do
    lambda {
      dumper = @pcap.open_dump(Tempfile.new(rand(0xffff).to_s).path)
      Dumper.should === dumper
      dumper.close
    }.should_not raise_error(Exception)
  end

  it "should be able to write packets to a dump file" do
    tmpfile = Tempfile.new(rand(0xffff).to_s).path
    dumper = @pcap.open_dump(tmpfile)
    dumper.write_pkt( Packet.from_string("i want to be a packet when i grow up") )
    dumper.flush
    dumper.close

    chk_pcap = Offline.new(tmpfile)
    pkt = chk_pcap.next
    pkt.should be_kind_of Packet
    pkt.body.should == "i want to be a packet when i grow up"
    chk_pcap.close
  end

  it "should raise an exception when opening a bad dump file" do
    lambda {
      @pcap.open_dump(File.join('','obviously','not','there'))
    }.should raise_error(Exception)
  end

  it "should return an empty String when an error has not occurred" do
    @pcap.error.should be_empty
  end

  it "should be able to compile a filter" do
    filter = @pcap.compile("ip")
    filter.should_not be_nil
    BPFProgram.should === filter
    filter.bf_len.should > 0
  end

  it "should detect invalid filter syntax when compiling" do
    lambda {
      @pcap.compile("ip and totally bogus")
    }.should raise_error(LibError)
  end

  it "should prevent double closes" do
    @pcap.close
    @pcap.should be_closed
    @pcap.should_not be_ready

    lambda {
      @pcap.close
    }.should_not raise_error(Exception)
  end

end

shared_examples_for "FFI::PCap::CaptureWrapper" do

  it "should pass packets to a block using loop()" do
    i = 0
    @pkt = nil
    @pcap.loop(:count => 2) do |this, pkt|
      this.should == @pcap
      pkt.should_not be_nil
      Packet.should === pkt
      i+=1
    end
    i.should == 2
  end

  it "should be able to get the next packet" do
    pkt = @pcap.next
    pkt.should_not be_nil
  end

  it "should be able to break out of a pcap loop()" do
    stopped = false
    i = 0

    @pcap.loop(:count => 3) do |this, pkt|
      stopped = true
      i+=1
      this.stop
    end

    i.should == 1
    stopped.should == true
  end

  it "should consume packets without a block passed to loop()" do
    lambda { @pcap.loop(:count => 3) }.should_not raise_error(Exception)
  end

  it "should be able to set a filter" do
    lambda {
      @pcap.set_filter("ip")
    }.should_not raise_error(Exception)
  end

  it "should detect invalid filter syntax in set_filter" do
    lambda {
      @pcap.set_filter("ip and totally bogus")
    }.should raise_error(LibError)
  end

  it_should_behave_like "FFI::PCap::CommonWrapper"
end

