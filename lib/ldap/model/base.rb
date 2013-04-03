require 'net/ldap'
require 'active_support/notifications'

require 'ldap/model/instrumentation'
require 'ldap/model/error'

module LDAP::Model
  class Base
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

    def self.connection
      @connection ||= Net::LDAP.new(
        host:       config['hostname'],
        port:       (config['port'] || 389).to_i,
        encryption: nil,
        auth:       {
          method:   :simple,
          username: config['username'],
          password: config['password']
        }
      )
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
        connection.search(options).tap {|result| event.update(:results => result.size)}
      end
    end

    def self.default_filter
      Net::LDAP::Filter.eq('objectClass', '*')
    end

    def self.find(dn, options = {})
      cn, base = dn.split(',', 2)

      find_one(options.merge(base: base, filter: Net::LDAP::Filter.construct(cn)))
    end

    def self.find_one(options)
      entry = search(options)

      if entry.respond_to?(:first) && entry.first.present?
        options[:raw_entry] ? entry.first : new(entry.first)
      end
    end

    def self.update_attribute(dn, attr, old_value, new_value)
      payload = {
        :dn => dn, :attr => attr,
        :old_value => loggable_attribute_value(attr, old_value),
        :new_value => loggable_attribute_value(attr, new_value)
      }

      instrument(:update, payload) do |event|
        success = old_value.nil? ?
          connection.add_attribute(dn, attr, new_value) :
          connection.replace_attribute(dn, attr, new_value)

        message = connection.get_operation_result.message

        event.update(:success => success, :message => message)

        [success, message]
      end
    end

    class << self
      # Minimal DSL
      %w( string binary computed ).each do |type|
        module_eval <<-RUBY
          def #{type}_attributes(list=nil)
            @#{type}_attributes ||= (list.present? ? list.to_set.freeze : [])
          end
        RUBY
      end

      def attributes
        @attributes ||= (string_attributes | binary_attributes).freeze
      end

      def export_attributes
        @export_attributes ||= (attributes | computed_attributes).freeze
      end

      def scope(type = nil)
        @scope ||= type
      end

      def define_attribute_methods(attributes)
        attributes.each do |method, args|
          attribute, *options = args

          define_method(method) { self[attribute] }

          define_method("#{method}=") do |value|
            update_attribute(attribute, value)
          end if options.include?(:readwrite)
        end
      end

      protected :connection

      protected
        def instrument(action, payload, &block)
          ActiveSupport::Notifications.instrument("#{action}.ldap", payload, &block)
        end

        def loggable_attribute_value(attribute, value)
          attribute.in?(binary_attributes) ?
            "[BINARY SHA:#{Digest::SHA1.hexdigest(value)}]" : value
        end
    end

    attr_reader :attributes, :dn

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

        h.update(attr => value.size < 2 ? value.first.to_s.presence : value)
      end.freeze
    end
    protected :initialize_from

    def [](name)
      attributes.fetch(name)
    end

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

    def update_attribute(attr, value)
      unless attr.in?(self.class.attributes)
        raise Error, "unknown attribute #{attr}"
      end

      value = value.to_s
      if attr.in?(self.class.binary_attributes)
        value = value.force_encoding('binary')
      end

      success, message =
        self.class.update_attribute(self.dn, attr, self[attr], value)

      if success
        return true
      else
        raise Error, message
      end
    end

    protected
      def method_missing(name, *args, &block)
        self[name.to_s]
      rescue KeyError
        super
      end

  end

end
