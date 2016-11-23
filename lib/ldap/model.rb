module LDAP
  module Model
    autoload :AD,              'ldap/model/ad'
    autoload :ISDS,            'ldap/model/isds'
    autoload :Base,            'ldap/model/base'
    autoload :ActiveRecord,    'ldap/model/active_record'
    autoload :Instrumentation, 'ldap/model/instrumentation'
  end
end

if defined?(Rails)
  require 'ldap/model/railtie'
end

if defined?(Hirb)
  require 'ldap/model/hirb'
end
