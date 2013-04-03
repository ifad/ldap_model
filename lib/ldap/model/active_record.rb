module LDAP::Model
  module ActiveRecord

    def ldap_backing(model, options = {})
      include ModelMethods

      @_ldap_model = model

      if options[:autosave].present?
        @_ldap_autosave = options[:autosave].map(&:to_s).freeze
        _check_ldap_autosave_attributes
        _setup_ldap_autosave_callback
      end
    end

    def ldap_model
      @_ldap_model
    end

    def ldap_autosave
      @_ldap_autosave
    end

    private
      def _check_ldap_autosave_attributes
        # Check validity of given attributes
        invalid = ldap_autosave.reject {|m| ldap_model.instance_methods.grep(/#{m}=$/)}
        if invalid.present?
          raise Error, "Invalid autosave attributes for #{ldap_model}: #{invalid.inspect}"
        end
      end

      def _setup_ldap_autosave_callback
        after_validation :if => proc { self.errors.empty? } do
          self.class.ldap_autosave.each do |attr|
            next unless changed_attributes.key?(attr)

            begin
              ldap_entry.public_send("#{attr}=", self[attr])
            rescue LDAP::Error => e
              errors.add(attr, "was refused by Active Directory: #{e.message}")
            end
          end
        end
      end

    module ModelMethods
      def ldap_entry
        @_ldap_entry ||= self.class.ldap_model.find(self.dn)
      end

      def reload(*)
        @_ldap_entry = nil
        super
      end
    end

  end
end
