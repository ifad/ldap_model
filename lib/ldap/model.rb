require 'ldap/model/base'
require 'ldap/model/ad'

if defined?(Rails)
  require 'ldap/model/railtie'
end

if defined?(Hirb)
  require 'ldap/model/hirb'
end
