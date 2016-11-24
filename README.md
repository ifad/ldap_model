# ldap-model

This is a work in progress. It's an ActiveModel-compliant class that
interfaces with LDAP servers.

On top of this, there are two classes that parse Active Directory Person and
Root attributes and provide convenient readers.

You can use this to provide a deep integration with Active Directory from your
application. Changing and resetting passwords included.

No tests for now, please have a look at the code.

## Usage

```ruby
LDAP_SERVER = {
  "hostname"   => "mydomain.com",
  "encryption" => :start_tls,
  "username"   => "my_ldap_user",
  "password"   => "my_ldap_password",
  "base"       => "DC=mydomain"
}

class Person < Model::AD::Person
  establish_connection LDAP_SERVER
end

Person.find('CN=John Smith,DC=mydomain')
=> #<Person dn: CN=John Smith,DC=mydomain>
```

## License

[MIT license](LICENSE)
