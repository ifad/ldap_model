module LDAP::Model
  class ISDS::Person < Base
    validates :givenName, presence: true
    validates :uid, presence: true

    string_attributes %w[
      uid
      givenName
      sn
      displayName
      mail
    ]

    default_filter do
      Net::LDAP::Filter.eq('objectClass', 'person')
    end

    class << self
      def find_by_account(account_name)
        find_by(filter: Net::LDAP::Filter.eq('uid', account_name))
      end
    end

    define_attribute_methods(
      # User attributes
      uid:              'uid',
      email:            'mail',
      first_name:       'givenName',
      last_name:        'sn',
      display_name:     'displayName'
    )

    def initialize_from(entry, options)
      super
      return if persisted?

      @attributes['objectClass'] = %w( top person organizationalperson inetorgperson )
    end

    def attributes
      return super if persisted?

      @cn = name
    end

    def uid
      if (uid = self['uid']).kind_of?(Array)
        uid.find {|x| self.dn.include?(x) }
      else
        uid
      end
    end

    def name
      @attributes['displayName'] || @attributes.values_at('givenName', 'sn').join(' ').presence
    end

  end
end
