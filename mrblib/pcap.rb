module Pcap
  class Capture
    def loop(count = nil, &block)
      dumped_pkts = 0
      while s = self.capture
        block.call(s)
        dumped_pkts += 1
        break if dumped_pkts == count
      end
      self
    end
    alias_method :each, :loop
    alias_method :each_packet, :loop
  end
end
