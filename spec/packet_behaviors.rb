require 'spec_helper'

shared_examples_for "FFI::PCap::Packet" do
  it "should supply a way to get a pointer for the body" do
    expect(@pkt.body_ptr).not_to be_nil

    expect(@pkt.body_ptr).to be_kind_of(FFI::Pointer)
  end

  it "should supply a way to get a String for the body" do
    expect(@pkt.body).not_to be_nil

    expect(@pkt.body).to be_kind_of(String)
  end

  it "should supply a timestamp as a Time object" do
    expect(@pkt.time).not_to be_nil

    expect(@pkt.time).to be_kind_of(Time)
  end

  it "should allow time timestamp to be changed" do
    t = Time.now

    @pkt.time = t
    expect(@pkt.time.to_i).to eq(t.to_i)
  end

  it "should return a deep copy of itself with copy()" do
    cp = @pkt.copy()

    expect(cp.object_id).not_to eq(@pkt.object_id)
    expect(cp.body_ptr.object_id).not_to eq(@pkt.body_ptr.object_id)
    expect(cp.body).to eq(@pkt.body)
  end

  it "should marshal and umarshal" do
    m = Marshal.dump(@pkt)
    unm = Marshal.load(m)

    expect(unm).to be_kind_of(@pkt.class)
    expect(unm.time.to_i).to eq(@pkt.time.to_i)
    expect(unm.body).to eq(@pkt.body)
  end
end

shared_examples_for "FFI::PCap::Packet populated" do
  it_should_behave_like "FFI::PCap::Packet"

  it "should have a non-zero packet length in the header" do
    expect(@pkt.length).not_to eq(0)
  end

  it "should have a non-zero captured length in the header" do
    expect(@pkt.captured).not_to eq(0)
  end

  it "should have a non-empty body" do
    expect(@pkt.body).not_to be_empty
  end

  it "should have a non-null body pointer" do
    expect(@pkt.body_ptr).not_to be_null
  end
end

shared_examples_for "FFI::PCap::Packet composed" do
  it "should return the expected header" do
    expect(@pkt.header).to be_kind_of(PacketHeader)
    expect(@pkt.header.len).to  eq(@test_body.size)
    expect(@pkt.header.caplen).to eq(@test_body.size)
    expect(@pkt.header.timestamp.to_time.to_i).to eq(0)
  end

  it "should return the expected body String" do
    expect(@pkt.body).to eq(@test_body)
  end

  it "should return a pointer to the expected body String" do
    expect(@pkt.body_ptr.read_string(@pkt.caplen)).to eq(@test_body)
  end
end
