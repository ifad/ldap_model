module LDAP::Model
  module ActiveRecord

    Error = LDAP::Model::Error

    def ldap_backing(model, options = {})
      include ModelMethods

      unless self.column_names.include?('dn')
        raise Error, "The #{self} model must have a 'dn' attribute containing the linked LDAP dn"
      end

      @_ldap_model = model
      @_ldap_options = options

      if ldap_options[:autosave].present?
        ldap_options[:autosave].map!(&:to_s)
        _check_ldap_autosave_attributes
        _setup_ldap_autosave_callback
      end

      if options[:create].present?
        ldap_options[:create].map!(&:to_s)
        _setup_ldap_create_callback
      end

      ldap_options.freeze
    end

    def ldap_model
      @_ldap_model
    end

    def ldap_options
      @_ldap_options
    end

    private
      def _check_ldap_autosave_attributes
        # Check validity of given attributes
        invalid = ldap_options[:autosave].reject {|m| ldap_model.instance_methods.grep(/#{m}=$/)}
        if invalid.present?
          raise Error, "Invalid autosave attributes for #{ldap_model}: #{invalid.inspect}"
        end
      end

      def _setup_ldap_create_callback
        before_create :_create_ldap_entry, :if => proc { self.ldap_entry.new_record? && self.errors.empty? }
      end

      def _setup_ldap_autosave_callback
        before_save :_autosave_ldap_attributes, :if => proc { self.errors.empty? }
      end

    module ModelMethods
      def ldap_entry
        @_ldap_entry ||= begin
          if new_record? || self.dn.blank?
            self.dn = "CN=#{self.name},#{self.class.ldap_model.base.first}"
          end

          entry = self.class.ldap_model.find(self.dn)
          if entry.nil? && self.class.ldap_options[:create]
            entry = self.class.ldap_model.new(dn: self.dn)
          end

          entry
        end
      end

      # Useful for LDAP imports
      #
      def ldap_entry=(entry)
        unless entry.is_a? self.class.ldap_model
          raise Error, "Invalid entry type: #{entry.class}, #{self.class.ldap_model.class} expected"
        end

        @_ldap_entry = entry
      end

      def reload(*)
        @_ldap_entry = nil
        super
      end

      protected
        def _autosave_ldap_attributes
          self.class.ldap_options[:autosave].each do |attr|
            next unless public_send("#{attr}_changed?")
            ldap_entry.public_send("#{attr}=", public_send(attr))
          end

          ldap_entry.save! unless ldap_entry.new_record? && self.class.ldap_options[:create]

        rescue Error => e
          errors.add(:ldap, e.message)
          raise ::ActiveRecord::RecordInvalid, self
        end

        def _create_ldap_entry
          self.class.ldap_options[:create].each do |attr|
            ldap_entry.public_send("#{attr}=", public_send(attr))
          end

          ldap_entry.save!
        rescue Error => e
          errors.add(:ldap, e.message)
          raise ::ActiveRecord::RecordInvalid, self
        end
    end

    # Call this from an initializer to disable LDAP connectivity from AR Models
    #
    def self.disable!
      %w[ ldap_backing ].each do |api|
        ::ActiveRecord::Base.singleton_class.instance_eval { define_method(api) {|*|} }
      end

      STDERR.puts "LDAP disabled. To test LDAP integration, define a `test' environment in #{Base.config_path}"
    end

  end
end
