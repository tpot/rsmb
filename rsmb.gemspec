# -*- encoding: utf-8 -*-

require File.expand_path('../lib/rsmb/version', __FILE__)

Gem::Specification.new do |gem|
  gem.name          = "rsmb"
  gem.version       = Rsmb::VERSION
  gem.summary       = %q{SMB packet library}
  gem.description   = %q{SMB packet library}
  gem.license       = "MIT"
  gem.authors       = ["Tim Potter"]
  gem.email         = "tpot@frungy.org"
  gem.homepage      = "https://rubygems.org/gems/rsmb"

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ['lib']

  gem.add_development_dependency 'rubygems-tasks', '~> 0.2'
  gem.add_development_dependency 'rspec', '~> 2.4'
  gem.add_development_dependency 'yard', '~> 0.7'
end
