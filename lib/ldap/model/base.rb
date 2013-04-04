require 'net/ldap'

require 'active_support/notifications'

require 'active_model/dirty'

require 'ldap/model/instrumentation'
require 'ldap/model/error'

module LDAP::Model
  class Base
    include ActiveModel::Dirty

    Error = LDAP::Model::Error # :nodoc:

    class << self
      delegate :logger, :logger=, :to => Instrumentation::LogSubscriber
    end

    def self.config
      @config ||= YAML.load_file(config_path).fetch(env).freeze
    end

    def self.config_path
      'config/ldap.yml'
    end

    def self.env
      defined?(Rails) ? Rails.env.to_s :
        (ENV['RAILS_ENV'] || ENV['RACK_ENV'] || 'development')
    end

    class << self
      def connection
        establish_connection unless connected?
        @connection
      end
      protected :connection
    end

    def self.establish_connection
      return true if connected?

      instrument(:connect, :config => config_path) do

        @connection = Net::LDAP.new(
          base:       config['base'],
          host:       config['hostname'],
          port:       (config['port'] || 389).to_i,
          encryption: config['encryption'],
          auth:       {
            method:   :simple,
            username: config['username'],
            password: config['password']
          }
        )

        unless @connection.bind
          reason = @connection.get_operation_result.message
          raise Error, "LDAP bind to #{config['hostname']} failed: #{reason}"
        end

      end

      true
    end

    def self.connected?
      !@connection.nil?
    end

    def self.all
      base.inject([]) do |result, dn|
        result.concat(search(base: dn).map {|entry| new(entry)})
      end
    end

    def self.search(options)
      options[:scope]      ||= scope
      options[:attributes] ||= attributes

      if options[:filter].present?
        options[:filter] &= default_filter
      else
        options[:filter] = default_filter
      end

      instrument(:search, options) do |event|
        (connection.search(options) || []).tap do |result|
          event.update(:results => result.size)
        end
      end
    end

    def self.default_filter
      Net::LDAP::Filter.eq('objectClass', '*')
    end

    def self.find(dn, options = {})
      find_one(options.merge(base: dn, scope: Net::LDAP::SearchScope_BaseObject))
    end

    def self.find_one(options)
      entry = search(options)

      if entry.respond_to?(:first) && entry.first.present?
        options[:raw_entry] ? entry.first : new(entry.first)
      end
    end

    def self.modify(dn, changes)
      instrument(:update, :dn => dn, :changes => loggable_changes(changes)) do |event|
        # Build the operations array
        operations = changes.inject([]) do |ops, (attr, (old, new))|
          op = if old.nil? then :add elsif new.nil? then :delete else :replace end
          ops << [op, attr, new]
        end

        success = connection.modify(:dn => dn, :operations => operations)
        message = connection.get_operation_result.message

        event.update(:success => success, :message => message)

        [success, message]
      end
    end

    class << self
      # Minimal DSL
      %w( string binary computed ).each do |type|
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
        @attributes ||= (string_attributes | binary_attributes)
      end

      def export_attributes
        @export_attributes ||= (attributes | computed_attributes)
      end

      def scope(type = nil)
        @scope ||= type
      end

      def base(base = nil)
        @base ||= Array.wrap(base)
      end

      def define_attribute_methods(attributes)
        mutable = []

        attributes.each do |method, args|
          attr, *options = args

          unless attr.in?(self.attributes)
            raise Error, "unknown attribute #{attribute}"
          end

          # Reader
          define_method(method) { self[attr] }

          # Writer
          if options.include?(:readwrite)
            define_method("#{method}=") {|val| self[attr] = val}
            mutable.push method
          end
        end

        super(mutable)
      end

      protected
        def instrument(action, payload, &block)
          ActiveSupport::Notifications.instrument("#{action}.ldap", payload, &block)
        end

        def loggable_changes(changes)
          changes.inject({}) do |ret, (attr, change)|
            if attr.in?(binary_attributes)
              change = change.map {|x| x.present? ? "[BINARY SHA:#{Digest::SHA1.hexdigest(x)}]" : ''}
            end

            ret.update(attr => change)
          end
        end
    end

    attr_reader :dn

    def initialize(entry)
      initialize_from(entry)
    end

    def reload
      initialize_from(self.class.find(self.dn, :raw_entry => true))
      self
    end

    def initialize_from(entry)
      @dn = entry.dn.dup.force_encoding('utf-8').freeze
      @attributes = self.class.attributes.inject({}) do |h, attr|

        value = entry[attr].reject(&:blank?).each do |v|
          v.force_encoding(attr.in?(self.class.binary_attributes) ? 'binary' : 'utf-8')
        end

        h.update(attr => value.size < 2 ? value.first : value)
      end

      @changed_attributes.try(:clear)
    end
    protected :initialize_from

    def attributes
      @attributes.dup
    end

    def save!
      return true unless changed?

      @previously_changed = changes
      success, message = self.class.modify(dn, changes)

      if success
        @changed_attributes.clear
        true
      else
        raise Error, "Save failed: #{message}"
      end
    end

    def save
      save! rescue false
    end

    def [](attr)
      @attributes.fetch(attr)
    end

    def []=(attr, value)
      if value.present?
        value = value.to_s

        if attr.in?(self.class.binary_attributes)
          value = value.force_encoding('binary')
        end
      else
        value = nil
      end

      if value != self[attr]
        public_send "#{attr}_will_change!"
        @attributes[attr] = value
      end
    end

    protected :[], :[]=

    def inspect
      attrs = self.class.string_attributes.inject([]) {|l,a| l << [a, self[a].inspect].join(': ')}
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

    protected
      def method_missing(name, *args, &block)
        self[name.to_s]
      rescue KeyError
        super
      end

  end

end
