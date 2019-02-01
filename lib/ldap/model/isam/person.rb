module LDAP::Model
  # This is a wrapper class for the wondrous IBM design that keeps Person
  # information in one tree, and Account information in another one. Thus
  # you are forced to mix and match and pray the gods will do justice one
  # day.
  #
  class ISAM::Person

    # Define new subclasses so not to pollute the base ones with
    # the connection and configuration happening via this class.
    #
    def self.person_class
      @_person_class ||= Class.new(ISDS::Person).tap {|c| const_set(:DelegatePerson, c) }
    end

    def self.account_class
      @_account_class ||= Class.new(ISAM::Account).tap {|c| const_set(:DelegateAccount, c) }
    end

    # Clear accessory subclasses on inheritance.
    #
    def self.inherited(subclass)
      %w( @_person_class @_account_class ).each do |ivar|
        subclass.instance_variable_set(ivar, nil)
      end
    end

    # Establish connection on both trees. These could be separate servers
    # however it has been always seen in the same one. If one day support
    # for different servers is needed it can be added here easily.
    #
    def self.establish_connection(config)
      unless config.key?('secAuthority')
        raise Error, "Please give the secAuthority name in config"
      end

      # Connect ISDS tree
      person_class.establish_connection(config.dup)

      # Connect ISAM tree
      account_class.establish_connection(config.dup)
      account_class.base "cn=Users,secAuthority=#{config['secAuthority']}"

      true
    end

    # Return true if both branches are connected.
    #
    def self.connected?
      person_class.connected? && account_class.connected?
    end

    # And now for the crazy ones - some metaprogramming to be DRY.
    #
    module DSL
      # Implement straightforward method delegation instead of relying on
      # ActiveSupport, both to use a descriptive name, but as well to not
      # use the fancy ball of eval'ed code in ActiveSupport, complicating
      # debugging and troubleshooting.
      #
      def delegate_class_method(name, options)
        to = options.fetch(:to)

        define_class_method(name) do |*args, &block|
          send(to).public_send(name, *args, &block)
        end
      end

      # Delegate class methods with person/account association. The starting
      # point is always the +person_class+. Then, depending on the number of
      # people to associate, two different strategies are selected.
      #
      def association_class_method(name, options)
        to   = options.fetch(:to)
        with = options.fetch(:with)

        define_class_method(name) do |*args, &block|
          associate(send(to).public_send(name, *args, &block), send(with))
        end
      end

      # Return error for read/write LDAP Model APIs, as the ISAM tree cannot
      # be written to.
      #
      def error_class_method(name)
        define_class_method(name) do |*args, &block|
          raise Error, "#{name} can't be implemented as ISAM is read-only"
        end
      end

      # Select and delegate instance methods from the given class to the
      # given target instance variable.
      #
      # Do not delegate setters, state-altering ones and ones defined by
      # +ActiveModel::Dirty+ - as these instances are read-only.
      #
      def delegate_public_instance_methods(options)
        from = options.fetch(:from)

        methods = (send(from).public_instance_methods - Object.methods).
          reject {|m| m =~ /(?:=|!|_changed\?|change|_will_change|_was)$/}

        target = options.fetch(:to)

        methods.each do |method|
          define_method(method) do |*args, &block|

            instance = instance_variable_get(target) # @person or @account

            if instance.nil?
              raise Error,
                "#{self.class}##{method} delegates to #{target} but it's nil"
            end

            instance.public_send(method, *args, &block)
          end
        end
      end

      private
        def associate(input, account_class)
          people = Array.wrap(input)

          # If the list of people is less than 5, issue separate queries
          # to the LDAP server. Otherwise, download all accounts and map
          # them using an intermediate hash map.
          #
          ret = if people.size > 5
            associate_many(people, account_class)
          else
            people.map {|p| associate_one(p, account_class) }
          end

          # If an Array was given as input, return an Array, else yield
          # a single entry.
          input.is_a?(Array) ? ret : ret.first
        end

        # Associates the given person entry with its corresponding
        # account information fetched from the other branch, using
        # the person DN as the key.
        #
        def associate_one(person, account_class)
          return unless person

          account = account_class.find_by_secdn(person.dn)

          new(person, account)
        end

        # Associates the given people list with their corresponding
        # account informations fetched from the other branch, using
        # an intermediate hash map holding temporarily all accounts
        # information prior to association.
        #
        def associate_many(people, account_class)
          accounts = account_class.all

          accounts_by_person_dn = accounts.inject({}) do |h, acct|
            h.update(acct.person_dn => acct)
          end

          people.map do |person|
            account = accounts_by_person_dn.fetch(person.dn, nil)
            new(person, account)
          end
        end

        # Utility to be DRY.
        def define_class_method(name, &code)
          singleton_class.instance_eval { define_method(name, &code) }
        end
    end

    extend DSL

    # Delegate class methods
    delegate_class_method :base,               to: :person_class
    delegate_class_method :scope,              to: :person_class
    delegate_class_method :default_filter,     to: :person_class

    # Delegate class methods to the +person_class+ adding associations with
    # the accounts information
    association_class_method :find_by_account, to: :person_class, with: :account_class
    association_class_method :find_by_email,   to: :person_class, with: :account_class
    association_class_method :all,             to: :person_class, with: :account_class
    association_class_method :search,          to: :person_class, with: :account_class
    association_class_method :find,            to: :person_class, with: :account_class
    association_class_method :find_by,         to: :person_class, with: :account_class
    association_class_method :find_one,        to: :person_class, with: :account_class

    # These can't be implemented as nothing can be written to the accounts
    # branch - so return an LDAP::Model::Error
    error_class_method :find_or_initialize
    error_class_method :modify
    error_class_method :add
    error_class_method :delete
    error_class_method :bind

    # Delegate selected public instance methods from the given class to the
    # given instance variable.
    delegate_public_instance_methods from: :account_class, to: :@account
    delegate_public_instance_methods from: :person_class,  to: :@person

    def initialize(person, account)
      @person = person
      @account = account
    end

    def has_account?
      !@account.nil?
    end
  end
end
