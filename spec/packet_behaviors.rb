shared_examples_for "PCap::Packet" do
  it "should have a header" do
    @pkt.header.should_not be_nil
    PCap::PacketHeader.should === @pkt.header
  end

  it "should supply a way to get a pointer for the body" do
    @pkt.body_ptr.should_not be_nil
    ::FFI::Pointer.should === @pkt.body_ptr
  end

  it "should supply a way to get a String for the body" do
    @pkt.body.should_not be_nil
    String.should === @pkt.body
  end

end

shared_examples_for "PCap::Packet populated" do
  it_should_behave_like "PCap::Packet"

  it "should have a non-zero packet length in the header" do
    @pkt.header.length.should_not == 0
  end

  it "should have a non-zero captured length in the header" do
    @pkt.header.captured.should_not == 0
  end

  it "should have a non-empty body" do
    @pkt.body.should_not be_empty
  end

  it "should have a non-null body pointer" do
    @pkt.body_ptr.should_not be_null
  end

end
