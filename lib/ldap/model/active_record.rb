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

      if ldap_options[:associations].present?
        _check_ldap_association_attributes
        _setup_ldap_association_callback
      end

      if ldap_options[:autosave].present?
        ldap_options[:autosave].map!(&:to_s)
        _check_ldap_autosave_attributes
        _setup_ldap_autosave_callback
      end

      if ldap_options[:create].present?
        ldap_options[:create].map!(&:to_s)
        _setup_ldap_create_callback
      end

      _setup_ldap_destroy_callback

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

      def _check_ldap_association_attributes
        ldap_options[:associations].each do |ldap_attribute, assoc_a|
          raise Error, "Invalid association :ldap_attribute for #{self.name}#ldap_backing: #{ldap_attribute}(is it defined in #{ldap_model}.define_attribute_methods?)" unless ldap_model.instance_methods.include? "#{ldap_attribute}=".to_sym
          assoc = self.reflect_on_association(assoc_a[0].to_sym)
          raise Error, "Invalid association class name for #{self.name}#ldap_backing: #{assoc_a[0]}" unless assoc
          raise Error, "LDAP backing is only supported for :has_many associations in #{self.name}#ldap_backing: #{assoc_a[0]}" unless assoc.macro == :has_many
          klass = assoc.klass
          raise Error, "Invalid association class name for #{self.name}#ldap_backing: #{assoc_a[0]}" unless klass
          raise Error, "Invalid assocation method for #{self.name}#ldap_backing: #{klass.name}.#{assoc_a[1]}" unless klass.instance_methods.include? assoc_a[1].to_sym
        end
      end

      # Appends methods to add/delete to/from the ldap array attribute to the before/after_add chain
      # for the association
      def _setup_ldap_association_callback
        ldap_options[:associations].each do |ldap_attribute,assoc_a|
          assoc = assoc_a[0]
          method = assoc_a[1]
          raise "Missing ldap_attribute" unless ldap_attribute
          raise "Missing association name" unless assoc
          raise "Missing association method" unless method

          self.class_eval <<-EOS
            def _ldap_add_#{assoc} obj
              ldap_entry.#{ldap_attribute} += [obj.#{method}] unless obj.nil?
              ldap_entry.save! unless ldap_entry.new_record? && self.class.ldap_options[:create]
            end
            after_add_for_#{assoc} << :_ldap_add_#{assoc}

            def _ldap_remove_#{assoc} obj
              ldap_entry.#{ldap_attribute} -= [obj.#{method}] unless obj.nil?
              ldap_entry.save! unless ldap_entry.new_record? && self.class.ldap_options[:create]
            end
            after_remove_for_#{assoc} << :_ldap_remove_#{assoc}
          EOS

          # Ideally, we want also to add an after_update callback on the child class, to check
          # for changes to the specified attribute and to propagate them to the ldap entry as well.
          # However, we encounter the annoying problem that the scope for the callback is either
          # the child object (if define_method used), or the parent *class* (if proc/lamdba used).
          # I don't think we have a foolproof programmatic way of determining the parent object
          # within the block. We could offload that responsibility by allowing ldap_backing() to
          # take a proc or method wherein the person programming the AR models could do it themselves,
          # but that's ugly. Luckily, we have not yet encountered a use case in our own systems that
          # requires this.
        end
      end

      def _setup_ldap_create_callback
        before_create :_create_ldap_entry
      end

      def _setup_ldap_autosave_callback
        before_save :_autosave_ldap_attributes
      end

      def _setup_ldap_destroy_callback
        before_destroy :_destroy_ldap_entry
      end

    module ModelMethods
      def ldap_entry
        @_ldap_entry ||= begin
          if new_record? || self.dn.blank?
            _cn = (self.respond_to?(:cn) ? self.cn : nil) || self.name
            self.dn = "CN=#{_cn},#{self.class.ldap_model.base.first}" unless self.dn
          end

          entry = self.class.ldap_model.find(self.dn)
          if entry.nil?
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
            ao = self.class.ldap_options[:associations]
            if ao && ao[attr.to_sym]
              # Construct new array from the sum of the AR association
              # associations are array [ assoc-name, assoc-method ]
              aa = ao[attr.to_sym]
              ldap_entry.public_send "#{attr}=", public_send(aa[0]).all.map(&aa[1].to_sym)
            else
              next unless public_send("#{attr}_changed?")
              ldap_entry.public_send("#{attr}=", public_send(attr))
            end
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

        def _destroy_ldap_entry
          ldap_entry.destroy
        end
    end

    # Call this from an initializer to disable LDAP connectivity from AR Models
    #
    class << self
      def disable!
        %w[ ldap_backing ].each do |api|
          ::ActiveRecord::Base.singleton_class.instance_eval { define_method(api) {|*|} }
        end

        @disabled = true
      end

      def disabled?
        !!@disabled
      end
    end

  end

  def self.disabled?
    LDAP::Model::ActiveRecord.disabled?
  end
end
