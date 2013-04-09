dev = "eth1"
cap = Pcap::Capture.open_live(dev, 1500)

cap.setfilter("icmp", true)
cap.each_packet do |pkt|
  ts = Time.at(pkt[0].to_f)
  print "#{ts} #{ts.usec} "
  pkt[3].each_byte do |b|
    printf("%02x ", b)
  end
  print "\n"
end
