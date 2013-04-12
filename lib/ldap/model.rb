module LDAP::Model
  autoload :AD,              'ldap/model/ad'
  autoload :Base,            'ldap/model/base'
  autoload :ActiveRecord,    'ldap/model/active_record'
  autoload :Instrumentation, 'ldap/model/instrumentation'
end

if defined?(Rails)
  require 'ldap/model/railtie'
end

if defined?(Hirb)
  require 'ldap/model/hirb'
end
