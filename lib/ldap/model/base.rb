require 'net/ldap'

require 'active_support/notifications'
require 'active_support/core_ext/array'
require 'active_support/core_ext/object' # try

require 'active_model'

require 'ldap/model/instrumentation'
require 'ldap/model/error'

module LDAP::Model
  class Base
    include ActiveModel::Dirty
    include ActiveModel::Validations

    Error = LDAP::Model::Error # :nodoc:

    class << self
      delegate :logger, :logger=, :to => Instrumentation::LogSubscriber
    end

    def self.connection
      raise Error, "Connection not established" unless connected?
      @connection
    end

    def self.config
      @config
    end

    def self.establish_connection(config)
      config['port'] ||= 389

      url = "ldap%s://%s@%s:%d/" % [
        ('s' if config['encryption']),
        config['username'],
        config['hostname'],
        config['port']
      ]

      @config = config.dup.freeze

      instrument(:connect, :url => url) do
        @connection = Net::LDAP.new(
          host:       config['hostname'],
          port:       config['port'].to_i,
          encryption: config['encryption'],
          auth:       {
            method:   :simple,
            username: config['username'],
            password: config['password']
          }
        )

        unless @connection.bind
          reason = @connection.get_operation_result.message
          @connection = nil
          raise Error, reason
        end

        base config['base'] if config['base'].present?
      end

      true
    rescue => e
      raise Error, "LDAP bind to #{config['hostname']}:#{config['port']} as #{config['username']} failed: #{e.message}"
    end

    def self.connected?
      !!@connection
    end

    def self.inherited(subclass)
      %w( @connection @base @scope @default_filter ).each do |ivar|
        subclass.instance_variable_set(ivar, instance_variable_get(ivar))
      end
    end

    def self.all(options = {})
      base.inject([]) do |result, dn|
        result.concat(search(options.merge(base: dn)))
      end
    end

    def self.search(options)
      raw_entry = options.delete(:raw_entry)

      options[:scope]      ||= scope
      options[:attributes] ||= attributes
      options[:connection] ||= connection

      if options[:filter].present?
        options[:filter] &= default_filter
      else
        options[:filter] = default_filter
      end

      instrument(:search, options) do |event|
        (options[:connection].search(options) || []).tap do |result|
          unless raw_entry
            result.map! {|entry| new(entry, :persisted => true)}
          end

          event.update(:results => result.size)
        end
      end
    end

    def self.default_filter(&block)
      if block
        @default_filter = block.call
      else
        @default_filter ||= Net::LDAP::Filter.eq('objectClass', '*').freeze
      end
    end

    def self.find(dn, options = {})
      raise Error, "Cannot .find with blank dn (#{dn.inspect})" if dn.blank?

      dn = dn.dup.force_encoding('binary')
      find_one(options.merge(base: dn, scope: Net::LDAP::SearchScope_BaseObject))
    end

    def self.find_or_initialize(dn)
      find(dn) || new(dn: dn)
    end

    def self.find_by(options)
      base.each do |branch|
        result = find_one(options.merge(base: branch))
        return result if result
      end
      nil
    end

    def self.find_one(options)
      entry = search(options)

      if entry.respond_to?(:first) && entry.first.present?
        entry.first
      end
    end

    def self.modify(dn, changes, operations)
      instrument(:update, :dn => dn, :changes => Array.wrap(changes)) do |event|
        success = connection.modify(:dn => dn, :operations => operations)
        message = connection.get_operation_result.message

        event.update(:success => success, :message => message)

        [success, message]
      end
    end

    def self.add(dn, attributes)
      attributes = attributes.reject {|k,v| v.blank?}
      instrument(:create, :dn => dn, :attributes => attributes.except(*binary_attributes)) do |event|
        success = connection.add(:dn => dn, :attributes => attributes)
        message = connection.get_operation_result.message

        event.update(:success => success, :message => message)

        [success, message]
      end
    end

    def self.delete(dn)
      instrument(:delete, dn: dn) do |event|
        success = connection.delete(dn: dn)
        message = connection.get_operation_result.message

        event.update(:success => success, :message => message)

        [success, message]
      end
    end

    def self.bind(username, password)
      instrument(:bind, :username => username) do |event|
        options = {:method => :simple, :username => username, :password => password}

        connection.bind(options).tap do |success|
          event.update(:success => success, :message => connection.get_operation_result.message)
        end
      end
    end

    class << self
      # Minimal DSL
      %w( string array binary computed boolean ).each do |type|
        module_eval <<-RUBY, __FILE__, __LINE__+1
          def #{type}_attributes(list=nil)
            @#{type}_attributes ||= superclass.respond_to?(:#{type}_attributes) ?
              superclass.#{type}_attributes : Set.new
            @#{type}_attributes |= list.to_set if list.present?
            @#{type}_attributes
          end
        RUBY
      end

      def attributes
        @attributes ||= (string_attributes | binary_attributes | array_attributes | boolean_attributes)
      end

      def inspectable_attributes
        (string_attributes | boolean_attributes)
      end

      def export_attributes
        @export_attributes ||= (attributes | computed_attributes)
      end

      def scope(type = nil)
        @scope ||= type
      end

      def base(base = nil)
        if base
          @base = Array.wrap(base)
        else
          @base || []
        end
      end

      def define_attribute_methods(attributes)
        attributes.each do |method, attr|
          unless self.attributes.include?(attr)
            raise Error, "unknown attribute #{attr}"
          end

          # Reader
          define_method(method) do
            if self.boolean_attributes.include?(attr)
              self[attr].to_s.downcase == 'true'
            else
              self[attr]
            end
          end

          # Writer
          writer = self.binary_attributes.include?(attr) ?
            proc {|val| self[attr] = val ? val.force_encoding('binary') : val} :
            proc {|val| self[attr] = val}

          define_method("#{method}=", &writer)
        end

        super(attributes.keys)
      end

      protected
        def instrument(action, payload, &block)
          ActiveSupport::Notifications.instrument("#{action}.ldap", payload, &block)
        end
    end

    attr_reader :dn, :cn

    def initialize(entry, options = {})
      initialize_from(entry, options)
    end

    def reload
      entry = self.class.find(self.dn, :raw_entry => true)
      raise Error, "Cannot find DN #{self.dn}" unless entry
      initialize_from(entry, :persisted => true)
      self
    end

    def initialize_from(entry, options)
      @persisted = options[:persisted] || false

      entry = entry.with_indifferent_access if entry.respond_to?(:with_indifferent_access)

      @dn = Array.wrap(entry[:dn]).first.dup.force_encoding('utf-8').freeze
      @cn = dn.match(/^cn=(.+?),/i) { $1 }
      @attributes = self.class.attributes.inject({}) do |h, attr|

        value = Array.wrap(entry[attr]).reject(&:blank?).map do |v|
          v.to_s.force_encoding(self.class.binary_attributes.include?(attr) ? 'binary' : 'utf-8')
        end

        h.update(attr => value.size < 2 ? value.first : value)
      end

      @changed_attributes.try(:clear)
    end
    protected :initialize_from

    def id
      dn
    end

    def persisted?
      @persisted
    end

    def new_record?
      !persisted?
    end

    def attributes
      @attributes.dup
    end

    def save!
      return create! unless persisted?
      return true unless changed?

      persisting do |changes|
        # Build the operations array
        operations = changes.inject([]) do |ops, (attr, (old_val, new_val))|
          op = if old_val.nil? then :add elsif new_val.nil? then :delete else :replace end
          ops << [op, attr, new_val]
        end
        success, message = self.class.modify(dn, loggable_changes, operations)

        raise Error, "LDAP save failed: #{message}" unless success
      end

      return true
    end

    def save
      save!
    rescue LDAP::Model::Error
      false
    end

    def create!
      persisting do
        success, message = self.class.add(dn, attributes.merge('cn' => cn))
        raise Error, "LDAP create failed: #{message}" unless success
      end

      return true
    end

    def changes
      normalize_changes(super)
    end


    def persisting(&block)
      changes = self.changes
      @previously_changed = self.changes

      ret = if self.class.config['readonly']
        puts "LDAP read-only, skipping save on #{self.dn} of #{self.changes.to_json}"
        true
      else
        block.call(changes)
      end

      @changed_attributes.clear
      @persisted = true

      return ret
    end
    protected :persisting

    def destroy!
      success, message = self.class.delete(dn)
      raise Error, "Destroy failed: #{message}" unless success
      @persisted = false

      return true
    end

    def destroy
      destroy!
    rescue LDAP::Model::Error
      false
    end

    def [](attr)
      value = @attributes.fetch(attr)
      if self.class.array_attributes.include?(attr)
        value = Array.wrap(value)
      end
      return value
    end

    def []=(attr, value)
      if value.present?
        value = if self.class.array_attributes.include?(attr)
          Array.wrap(value)
        else
          value.to_s
        end

        if self.class.binary_attributes.include?(attr)
          value = value.force_encoding('binary')
        end
      else
        value = nil
      end

      changed = if self.class.array_attributes.include?(attr)
        Array.wrap(value).to_set != self[attr].to_set
      else
        value != self[attr]
      end

      if changed
        public_send "#{attr}_will_change!"
        @attributes[attr] = value
      end
    end

    protected :[], :[]=

    def boolean_attributes
      self.class.boolean_attributes
    end

    protected :boolean_attributes

    def inspect
      attrs = self.class.inspectable_attributes.inject([]) {|l,a| l << [a, self[a].inspect].join(': ')}
      %[#<#{self.class.name} dn: #@dn", #{attrs.join(', ')}>]
    end

    def to_hash(attrs = nil)
      (attrs || self.class.export_attributes).inject({'dn' => dn}) do |h, attr|
        value = self.respond_to?(attr) ? self.public_send(attr) : self[attr]
        h.update(attr => value)
      end
    end

    def as_json(options)
      return to_hash if options.blank?

      options.symbolize_keys!
      attrs = self.class.export_attributes
      attrs &= Array.wrap(options[:only]).map(&:to_s)   if options.key?(:only)
      attrs -= Array.wrap(options[:except]).map(&:to_s) if options.key?(:except)

      to_hash(attrs)
    end

    def loggable_changes
      changes.inject({}) do |ret, (attr, change)|
        if self.class.binary_attributes.include?(attr)
          change = change.map {|x| x.present? ? "[BINARY SHA:#{Digest::SHA1.hexdigest(x)}]" : ''}
        end

        ret.update(attr => change)
      end
    end

    def to_ary
      [self]
    end

    protected
      def method_missing(method, *args, &block)
        if m = /(\w+)(=?)/.match(method)
          name, setter = m[1], m[2].present?
        end

        if name.nil? || !self.class.attributes.include?(name)
          return super
        end

        if setter
          self[name] = args.first
        else
          self[name]
        end
      end
    private

    def normalize_changes(changes)
      # Set boolean attributes according to LDAP standard
      changes.inject({}) do |res, (attr_name, ary)|
        res[attr_name] = if boolean_attributes.include?(attr_name)
          ary.map {|change| change.to_s.downcase == 'true' ? 'TRUE' : 'FALSE' }
        else
          ary
        end

        res
      end
    end
  end

end
