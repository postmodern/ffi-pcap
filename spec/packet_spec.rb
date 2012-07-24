require 'spec_helper'
require 'packet_behaviors'

describe Packet do
  describe 'created using new() with a body string and nil header' do
    before(:all) do
      @test_body = "\xde\xad\xbe\xef"
      @pkt = described_class.new(nil, @test_body)
    end

    it_should_behave_like "FFI::PCap::Packet composed"
  end

  describe 'created using new() with a Header and pointer to body' do
    before(:all) do
      @test_body = "\xde\xad\xbe\xef\xba\xbe"

      @pkt = described_class.new(
        PacketHeader.new(:caplen => @test_body.size, :len => @test_body.size),
        FFI::MemoryPointer.from_string(@test_body)
      )
    end

    it_should_behave_like "FFI::PCap::Packet composed"
  end

  describe 'created with from_string()' do
    before(:all) do
      @test_body = "\xde\xad\xbe\xef"
      @pkt = described_class.from_string("\xde\xad\xbe\xef")
    end
  
    it_should_behave_like "FFI::PCap::Packet composed"
  end

  describe 'provided by a libpcap savefile using next()' do
    before(:all) do
      @pcap = FFI::PCap.open_offline(PCAP_TESTFILE)
      @pkt = @pcap.next()
    end

    after(:all) { @pcap.close }

    it_should_behave_like "FFI::PCap::Packet populated"
  end

  describe 'provided by a libpcap savefile using loop()' do
    before(:all) do
      @pcap = FFI::PCap.open_offline(PCAP_TESTFILE)
      @pkt = nil

      # we use copy inside the loop because libpcap's loop() frees or reuses 
      # memory for packets after each call to the handler.
      @pcap.loop(:count => 1) { |this,pkt| @pkt = pkt.copy }
    end

    after(:all) { @pcap.close() }

    it_should_behave_like "FFI::PCap::Packet populated"
  end

  describe "error detection for new()" do
    subject { described_class }

    let(:buffer) { FFI::MemoryPointer.new(256) }

    it "should raise an error when two nil values are supplied" do
      lambda { subject.new(nil,nil)}.should raise_error(Exception)
    end

    it "should raise an error for an invalid header" do
      lambda { 
        subject.new(Object.new, buffer)
      }.should raise_error(Exception)
    end

    it "should raise an error for a nil header without a string body" do
      lambda { 
        subject.new(nil, buffer)
      }.should raise_error(Exception)
    end

    it "should raise an error for a valid header but an invalid body pointer" do
      lambda { 
        subject.new(PacketHeader.new, "hellotest")
      }.should raise_error(Exception)
    end

    it "should not raise an error for a PacketHeader and a pointer" do
      lambda { 
        subject.new(PacketHeader.new, buffer)
      }.should_not raise_error(Exception)
    end

    it "should not raise an error for a pointer and a pointer" do
      lambda { 
        subject.new(FFI::MemoryPointer.new(20), buffer)
      }.should_not raise_error(Exception)
    end

    it "should not raise an error for a nil and a string" do
      lambda { 
        subject.new(nil, "hellothere")
      }.should_not raise_error(Exception)
    end
  end
end
