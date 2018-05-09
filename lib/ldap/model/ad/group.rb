module LDAP::Model
  class AD::Group < Base
    include AD::Timestamps

    validates :cn, presence: true

    string_attributes %w[
      name
      description
      groupType
      mail
      targetAddress
      displayName
      sAMAccountName
      managedBy
    ]

    array_attributes %w[
      member
      proxyAddresses
    ]

    define_attribute_methods(
      :name            => 'name',
      :description     => 'description',
      :mail            => 'mail',
      :target_address  => 'targetAddress',
      :proxy_addresses => 'proxyAddresses',
      :display_name    => 'displayName',
      :account_name    => 'sAMAccountName',
      :members         => 'member',
      :managed_by      => 'managedBy',
    )

    # AD Group Types
    ADS_GROUP_TYPE_GLOBAL_GROUP       = 0x00000002
    ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP = 0x00000004
    ADS_GROUP_TYPE_LOCAL_GROUP        = 0x00000004
    ADS_GROUP_TYPE_UNIVERSAL_GROUP    = 0x00000008
    ADS_GROUP_TYPE_SECURITY_ENABLED   = 0x80000000

    class << self
      def default_filter
        only_groups = Net::LDAP::Filter.eq('objectClass', 'group')
        with_cn     = Net::LDAP::Filter.pres('cn')

        only_groups & with_cn
      end

      # Find by sAMAccountName
      # FIXME DRY with Person
      def find_by_account(account_name)
        find_by(filter: Net::LDAP::Filter.eq('sAMAccountName', account_name))
      end
    end

    def type
      if (self.type_id & ADS_GROUP_TYPE_SECURITY_ENABLED) > 0
        :security
      else
        :distribution
      end
    end

    def type=(type)
      if type == :security
        self.type_id |= ADS_GROUP_TYPE_SECURITY_ENABLED
      elsif type == :distribution
        self.type_id &= ~ADS_GROUP_TYPE_SECURITY_ENABLED
      else
        raise Error, "Invalid type: #{type}, must be one of :security or :distribution"
      end
    end

    def scope
      type = self.type_id

      if (type & ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP) > 0
        :local
      elsif (type & ADS_GROUP_TYPE_GLOBAL_GROUP) > 0
        :global
      elsif (type & ADS_GROUP_TYPE_UNIVERSAL_GROUP) > 0
        :universal
      end
    end

    def scope=(scope)
      if scope == :local
        self.type_id &= ~(
          ADS_GROUP_TYPE_GLOBAL_GROUP|ADS_GROUP_TYPE_UNIVERSAL_GROUP)
        self.type_id |= ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP

      elsif scope == :global
        self.type_id &= ~(
          ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP|ADS_GROUP_TYPE_UNIVERSAL_GROUP)
        self.type_id |= ADS_GROUP_TYPE_GLOBAL_GROUP

      elsif scope == :universal
        self.type_id &= ~(
          ADS_GROUP_TYPE_GLOBAL_GROUP|ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP)
        self.type_id |= ADS_GROUP_TYPE_UNIVERSAL_GROUP

      else
        raise Error, "Invalid scope: #{scope.inspect}, must be one of :local, :global or :universal"
      end
    end

    def type_id
      self['groupType'].to_i & 0xffffffff
    end

    def type_id=(type)
      self['groupType'] = type.to_s
    end

    def initialize_from(entry, options)
      super
      return if persisted?

      @attributes['objectClass']   = %w( top group )
      @attributes['groupType'  ] ||= ADS_GROUP_TYPE_GLOBAL_GROUP.to_s
    end
  end
end
