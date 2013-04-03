# Hirb view for LDAP models
#
Hirb.add_dynamic_view('LDAP::Model::Base', :helper => :auto_table) do |obj|
  {:fields => obj.class.string_attributes}
end
