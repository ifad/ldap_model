# -*- encoding: utf-8 -*-
require File.expand_path('../lib/ldap/model/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ['Marcello Barnaba']
  gem.email         = ['vjt@openssl.it']
  gem.description   = 'ActiveModel compliant model for LDAP directories'
  gem.summary       = 'ActiveModel on LDAP'
  gem.homepage      = 'http://github.com/ifad/ldap_model'

  gem.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.name          = 'ldap_model'
  gem.require_paths = %w( lib )
  gem.version       = LDAP::Model::VERSION

  gem.add_dependency 'net-ldap', '>= 0.16.0'
  gem.add_dependency 'activemodel', '>= 3.2', '< 5.0'
end
