module LDAP::Model
  class AD::Group < Base
    validates :cn, presence: true

    string_attributes %w[ name description ]

    array_attributes %w[ member ]

    def self.default_filter
      only_groups = Net::LDAP::Filter.eq('objectClass', 'group')
      with_cn     = Net::LDAP::Filter.pres('cn')

      only_groups & with_cn
    end

    def attributes
      return super if persisted?

      super.tap do |a|
        a.update(
          'objectClass' => %w( top group )
        )
      end
    end
  end
end
