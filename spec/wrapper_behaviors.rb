require 'spec_helper'
require 'tempfile'

shared_examples_for "FFI::PCap::CommonWrapper" do
  it "should indicate readiness" do
    expect(@pcap.ready?).to eq(true)
  end

  it "should have a datalink" do
    datalink = @pcap.datalink
    expect(datalink.value).not_to be_nil
    expect(Numeric).to be === datalink.value
    expect(datalink.name).not_to be_empty
  end

  it "should be able to open a dump file" do
    expect {
      dumper = @pcap.open_dump(Tempfile.new(rand(0xffff).to_s).path)
      expect(Dumper).to be === dumper
      dumper.close
    }.not_to raise_error
  end

  it "should be able to write packets to a dump file" do
    tmpfile = Tempfile.new(rand(0xffff).to_s).path
    dumper = @pcap.open_dump(tmpfile)
    dumper.write_pkt( Packet.from_string("i want to be a packet when i grow up") )
    dumper.flush
    dumper.close

    chk_pcap = Offline.new(tmpfile)
    pkt = chk_pcap.next
    expect(pkt).to be_kind_of Packet
    expect(pkt.body).to eq("i want to be a packet when i grow up")
    chk_pcap.close
  end

  it "should raise an exception when opening a bad dump file" do
    expect {
      @pcap.open_dump(File.join('','obviously','not','there'))
    }.to raise_error(Exception)
  end

  it "should return an empty String when an error has not occurred" do
    expect(@pcap.error).to be_empty
  end

  it "should be able to compile a filter" do
    filter = @pcap.compile("ip")
    expect(filter).not_to be_nil
    expect(BPFProgram).to be === filter
    expect(filter.bf_len).to be > 0
  end

  it "should detect invalid filter syntax when compiling" do
    expect {
      @pcap.compile("ip and totally bogus")
    }.to raise_error(LibError)
  end

  it "should prevent double closes" do
    @pcap.close
    expect(@pcap).to be_closed
    expect(@pcap).not_to be_ready

    expect {
      @pcap.close
    }.not_to raise_error
  end
end

shared_examples_for "FFI::PCap::CaptureWrapper" do
  it "should pass packets to a block using loop()" do
    i = 0
    @pkt = nil
    @pcap.loop(:count => 2) do |this, pkt|
      expect(this).to eq(@pcap)
      expect(pkt).not_to be_nil
      expect(Packet).to be === pkt
      i+=1
    end
    expect(i).to eq(2)
  end

  it "should be able to get the next packet" do
    pkt = @pcap.next
    expect(pkt).not_to be_nil
  end

  it "should be able to break out of a pcap loop()" do
    stopped = false
    i = 0

    @pcap.loop(:count => 3) do |this, pkt|
      stopped = true
      i+=1
      this.stop
    end

    expect(i).to eq(1)
    expect(stopped).to eq(true)
  end

  it "should consume packets without a block passed to loop()" do
    expect { @pcap.loop(:count => 3) }.not_to raise_error
  end

  it "should be able to set a filter" do
    expect {
      @pcap.set_filter("ip")
    }.not_to raise_error
  end

  it "should detect invalid filter syntax in set_filter" do
    expect {
      @pcap.set_filter("ip and totally bogus")
    }.to raise_error(LibError)
  end

  it_should_behave_like "FFI::PCap::CommonWrapper"
end
