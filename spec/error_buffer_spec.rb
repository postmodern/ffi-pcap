require 'spec_helper'

describe ErrorBuffer do
  subject { ErrorBuffer.create }

  it "should have a default size of 256" do
    subject.size.should == 256
  end

  it "should return an error message with to_s" do
    subject.to_s.should be_empty

    FFI::PCap.pcap_open_offline("/this/file/wont/exist",subject)

    subject.to_s.should_not be_empty
  end
end
