module LDAP::Model

  module AD::Timestamps
    def self.included(base)
      base.instance_eval do
        string_attributes %w[ whenCreated whenChanged ]
      end
    end

    def created_at
      if self['whenCreated']
        AD.asn1_to_time(self['whenCreated'])
      end
    end

    def updated_at
      if self['whenChanged']
        AD.asn1_to_time(self['whenChanged'])
      end
    end
  end

end
