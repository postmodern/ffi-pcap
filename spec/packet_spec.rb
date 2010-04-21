require 'spec_helper'
require 'packet_behaviors'

describe Packet do
  describe 'created using new() with a body string and nil header' do
    before(:all) do
      @test_body = "\xde\xad\xbe\xef"
      @pkt = Packet.new(nil, @test_body)
    end

    it_should_behave_like "PCap::Packet composed"

  end

  describe 'created using new() with a Header and pointer to body' do
    before(:all) do
      @test_body = "\xde\xad\xbe\xef\xba\xbe"
      l = @test_body.size
      body = FFI::MemoryPointer.from_string(@test_body)
      @pkt = Packet.new(PacketHeader.new(:caplen => l, :len => l), body)
    end

    it_should_behave_like "PCap::Packet composed"

  end

  describe 'created with from_string()' do
    before(:all) do
      @test_body = "\xde\xad\xbe\xef"
      @pkt = Packet.from_string("\xde\xad\xbe\xef")
    end
  
    it_should_behave_like "PCap::Packet composed"

  end


  describe 'provided by a libpcap savefile using next()' do
    before(:all) do
      @pcap = PCap.open_offline(PCAP_TESTFILE)
      @pkt = @pcap.next()
    end

    after(:all) do
      @pcap.close()
    end

    it_should_behave_like "PCap::Packet populated"
  end

  describe 'provided by a libpcap savefile using loop()' do
    before(:all) do
      @pcap = PCap.open_offline(PCAP_TESTFILE)
      @pkt = nil
      # we use copy inside the loop because libpcap's loop() frees or reuses 
      # memory for packets after each call to the handler.
      @pcap.loop(:count => 1) {|this,pkt| @pkt = pkt.copy }
    end

    after(:all) do
      @pcap.close()
    end

    it_should_behave_like "PCap::Packet populated"
  end


  describe "error detection for new()" do
    it "should raise an error when two nil values are supplied" do
      lambda { Packet.new(nil,nil)}.should raise_error(Exception)
    end

    it "should raise an error for an invalid header" do
      lambda { 
        Packet.new(Object.new, FFI::MemoryPointer.new(256))
      }.should raise_error(Exception)
    end

    it "should raise an error for a nil header without a string body" do
      lambda { 
        Packet.new(nil, FFI::MemoryPointer.new(256))
      }.should raise_error(Exception)
    end

    it "should raise an error for a valid header but an invalid body pointer" do
      lambda { 
        Packet.new(PacketHeader.new, "hellotest")
      }.should raise_error(Exception)
    end

    it "should not raise an error for a PacketHeader and a pointer" do
      lambda { 
        Packet.new(PacketHeader.new, FFI::MemoryPointer.new(256))
      }.should_not raise_error(Exception)
    end

    it "should not raise an error for a pointer and a pointer" do
      lambda { 
        Packet.new(FFI::MemoryPointer.new(20), FFI::MemoryPointer.new(256))
      }.should_not raise_error(Exception)
    end

    it "should not raise an error for a nil and a string" do
      lambda { 
        Packet.new(nil, "hellothere")
      }.should_not raise_error(Exception)

    end

  end
end
