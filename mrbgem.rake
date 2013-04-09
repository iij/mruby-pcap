MRuby::Gem::Specification.new('mruby-pcap') do |spec|
  spec.license = 'MIT'
  spec.authors = 'Internet Initiative Japan Inc.'

  spec.cc.include_paths << "#{build.root}/src"
  spec.linker.libraries << 'pcap'
end
