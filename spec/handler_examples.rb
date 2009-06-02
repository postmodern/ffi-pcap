require 'pcap_ffi/handler'

require 'spec_helper'

shared_examples_for "Handler" do
  it "must have a datalink" do
    datalink = @pcap.datalink

    datalink.value.should_not be_nil
    datalink.name.should_not be_empty
  end

  it "should pass packets to a callback" do
    @pcap.callback do |user,header,bytes|
      header.captured.should_not == 0
      header.length.should_not == 0

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

  it "should be able to open a dump file" do
    lambda {
      dumper = @pcap.open_dump(Tempfile.new.path)
      dumper.close
    }.should_not raise_error(RuntimeError)
  end

  it "should raise an exception when opening a bad dump file" do
    lambda {
      @pcap.open_dump(File.join('','obviously','not','there'))
    }.should raise_error(RuntimeError)
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

  it "should prevent double closes" do
    @pcap.close
    @pcap.should be_closed

    lambda {
      @pcap.close
    }.should_not raise_error(StandardError)
  end
end
