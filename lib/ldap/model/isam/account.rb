module LDAP::Model
  # Mapping for the secAuthority tree on ISAM, holding account information.
  #
  # How much braindead this IBM design is only IBM knows. You reading this,
  # I feel your pain.
  #
  class ISAM::Account < Base
    default_filter do
      Net::LDAP::Filter.eq('objectClass', 'secUser')
    end

    string_attributes %w[
      principalName

      secLoginType
      secUUID
      secDomainId
      secDN
      secAuthority

      secCertDN
      secCertSerialNumber

      secHasPolicy
      secAcctValid
      secPwdValid

      secPwdLastChanged
      secPwdLastUsed
    ]

    define_attribute_methods(
      principal_name:     'principalName',
      login_type:         'secLoginType',
      uuid:               'secUUID',
      domain_id:          'secDomainId',
      person_dn:          'secDN',
      authority:          'secAuthority',
      certificate_dn:     'secCertDN',
      certificate_serial: 'secCertSerialNumber'
    )

    def self.find_by_secdn(dn)
      find_by(filter: Net::LDAP::Filter.eq('secDN', dn))
    end

    def save!
      raise Error, "Do not even think about saving this"
    end

    def has_policy?
      read_boolean('secHasPolicy')
    end

    def account_valid?
      read_boolean('secAcctValid')
    end

    def password_valid?
      read_boolean('secPwdValid')
    end

    def password_changed_at
      read_timestamp('secPwdLastChanged')
    end

    def password_used_at
      read_timestamp('secPwdLastUsed')
    end

    protected
      def read_boolean(attribute)
        @attributes[attribute] == 'TRUE'
      end

      def read_timestamp(attribute)
        Time.parse(@attributes[attribute])
      end
  end
end
