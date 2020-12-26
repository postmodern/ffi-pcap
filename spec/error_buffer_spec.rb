require 'spec_helper'

describe ErrorBuffer do
  it "should have a default size of 256" do
    expect(subject.size).to eq(256)
  end

  it "should return an error message with to_s" do
    expect(subject.to_s).to be_empty

    PCap.pcap_open_offline("/this/file/wont/exist",subject)

    expect(subject.to_s).not_to be_empty
  end
end
