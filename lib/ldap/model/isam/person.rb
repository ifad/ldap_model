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
    class DelegatePerson  < ISDS::Person;  end
    class DelegateAccount < ISAM::Account; end

    # Establish connection on both trees. These could be separate servers
    # however it has been always seen in the same one. If one day support
    # for different servers is needed it can be added here easily.
    #
    def self.establish_connection(config)
      unless config.key?('secAuthority')
        raise Error, "Please give the secAuthority name in config"
      end

      # Connect ISDS tree
      DelegatePerson.establish_connection(config.dup)

      # Connect ISAM tree
      DelegateAccount.establish_connection(config.dup)
      DelegateAccount.base "cn=Users,secAuthority=#{config['secAuthority']}"

      true
    end

    # And now for the crazy ones - some metaprogramming to be DRY.
    #
    module DSL
      # Implement straightforward method delegation instead of relying on
      # ActiveSupport, both to use a descriptive name, but as well to not
      # use the fancy ball of eval'ed code in ActiveSupport, complicating
      # debugging and troubleshooting.
      #
      def delegate_method(name, options)
        to = options.fetch(:to)

        define_method(name) do |*args, &block|
          to.public_send(name, *args, &block)
        end
      end

      # Select and delegate instance methods from the given class to the
      # given target instance variable.
      #
      # Do not delegate setters, state-altering ones and ones defined by
      # +ActiveModel::Dirty+ - as these instances are read-only.
      #
      def delegate_public_instance_methods(options)
        klass = options.fetch(:from)

        methods = (klass.public_instance_methods - Object.methods).
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

      # Delegate class methods with person/account association. The starting
      # point is always the DelegatePerson. Then, depending on the number of
      # people to associate, two different strategies are selected.
      #
      def association_method(name, options)
        to   = options.fetch(:to)
        with = options.fetch(:with)

        define_method(name) do |*args, &block|
          associate(to.public_send(name, *args, &block), with)
        end
      end

      # Return error for read/write LDAP Model APIs, as the ISAM tree cannot
      # be written to.
      #
      def error_method(name)
        define_method(name) do |*args, &block|
          raise Error, "#{name} can't be implemented as ISAM is read-only"
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
    end

    class << self
      extend DSL

      # Delegate class methods
      delegate_method :base,               to: DelegatePerson
      delegate_method :scope,              to: DelegatePerson
      delegate_method :default_filter,     to: DelegatePerson

      # Delegate class methods to the DelegatePerson adding associations with
      # the accounts information
      association_method :find_by_account, to: DelegatePerson, with: DelegateAccount
      association_method :find_by_email,   to: DelegatePerson, with: DelegateAccount
      association_method :all,             to: DelegatePerson, with: DelegateAccount
      association_method :search,          to: DelegatePerson, with: DelegateAccount
      association_method :find,            to: DelegatePerson, with: DelegateAccount
      association_method :find_by,         to: DelegatePerson, with: DelegateAccount
      association_method :find_one,        to: DelegatePerson, with: DelegateAccount

      # These can't be implemented as nothing can be written to the accounts
      # branch - so return an LDAP::Model::Error
      error_method :find_or_initialize
      error_method :modify
      error_method :add
      error_method :delete
      error_method :bind
    end

    extend DSL

    # Delegate selected public instance methods from the given class to the
    # given instance variable.
    delegate_public_instance_methods from: DelegateAccount, to: :@account
    delegate_public_instance_methods from: DelegatePerson,  to: :@person

    def initialize(person, account)
      @person = person
      @account = account
    end

    def has_account?
      !@account.nil?
    end
  end
end
