module LDAP::Model
  module ActiveRecord

    Error = LDAP::Model::Error

    def ldap_backing(model, options = {})
      include ModelMethods

      unless self.column_names.include?('dn')
        raise Error, "The #{self} model must have a 'dn' attribute containing the linked LDAP dn"
      end

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
        before_save :_autosave_ldap_attributes, :if => proc { self.errors.empty? }
      end

    module ModelMethods
      def ldap_entry
        @_ldap_entry ||= self.class.ldap_model.find(self.dn)
      end

      def reload(*)
        @_ldap_entry = nil
        super
      end

      protected
        def _autosave_ldap_attributes
          self.class.ldap_autosave.each do |attr|
            next unless changed_attributes.key?(attr)
            ldap_entry.public_send("#{attr}=", self[attr])
          end

          ldap_entry.save!

        rescue Error => e
          errors.add(:ldap, "save failed: #{e.message}")
        end
    end

  end
end
