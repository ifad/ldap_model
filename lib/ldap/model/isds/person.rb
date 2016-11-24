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

    class << self
      def filter_only_person
        Net::LDAP::Filter.eq('objectClass', 'person')
      end
    end

    # AD Root settings
    def root
      @root ||= self.class.root
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

      @attributes['objectClass']          = %w( top person organizationalPerson user )
      @attributes['userAccountControl'] ||= '544' # Normal user + No password required

    end

    def attributes
      return super if persisted?

      @cn = name

      super.tap do |attrs|
        attrs['displayName']       ||= name
      end
    end

    def name
      @attributes['name'] || @attributes.values_at('givenName', 'sn').join(' ').presence
    end

    def account_flags
      self['userAccountControl'].to_i
    end

  end
end
