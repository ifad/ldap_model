require 'ldap/model/version'
require 'ldap/model/base'

if defined?(::Hirb)
  ::Hirb.add_dynamic_view('LDAP::Base', :helper => :auto_table) do |obj|
    {:fields => obj.class.string_attributes}
  end
end
