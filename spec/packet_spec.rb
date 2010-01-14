require 'spec_helper'
require 'packet_behaviors'

describe Packet do
  describe 'composing one' do
    before(:all) do
      @pkt = Packet.from_string("\xde\xad\xbe\xef")
    end
  
    it_should_behave_like "PCap::Packet populated"
  end
end
