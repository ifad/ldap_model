module LDAP::Model
  class AD::Person < Base
    include AD::Timestamps

    autoload :Avatar, 'ldap/model/ad/person/avatar'

    validates :sAMAccountName, :givenName, presence: true

    binary_attributes %w[
      thumbnailPhoto
    ]

    string_attributes %w[
      givenName
      sn
      name
      displayName
      mail
      sAMAccountName
      userPrincipalName
      accountExpires
      pwdLastSet
      userAccountControl
      badPwdCount
      badPasswordTime
      lockoutTime
      telephoneNumber
      roomNumber
      mobile
      otherMobile
      otherMailbox
      employeeType
      employeeNumber
      employeeID
      division
      targetAddress
      c
      co
      l
    ]

    array_attributes %w[
      memberOf
      proxyAddresses
    ]

    computed_attributes %w[
      active?
      extension
      created_at
      updated_at
      expires_at
      valid_password?
      locked_out?
      disabled?
      password_expires_at
      password_changed_at
    ]

    class << self

      def root
        AD::Root.find
      end

      def filter_only_person
        Net::LDAP::Filter.eq('objectClass', 'person')
      end

      # Get accounts that are not expired. Rules:
      #
      # 1. accountExpires is greater than now
      # 2. accountExpires is equal to 0x7fffffffffffffff
      # 3. accountExpires is equal to 0.
      #
      # The 2. and 3. rules indicate that the account never expires.
      #
      # http://msdn.microsoft.com/en-us/library/windows/desktop/ms675098(v=vs.85).aspx
      #
      def filter_active_person
        (Net::LDAP::Filter.ge('accountExpires', AD.now.to_s) |
         Net::LDAP::Filter.eq('accountExpires', '0'))
      end

      # Find by sAMAccountName
      # FIXME DRY with Group
      #
      def find_by_account(account_name)
        find_by(filter: Net::LDAP::Filter.eq('sAMAccountName', account_name))
      end

      # Validate the provided user credentials
      #
      def valid_credentials?(dn, password)
        bind(dn, password)
      end

      def valid_account?(account, password)
        if person = find_by_account(account)
          bind(person.dn, password)
        end
      end

      def active
        all(filter: filter_active_person)
      end

    end

    # AD Root settings
    def root
      @root ||= self.class.root
    end

    delegate :min_password_length, :password_history_length,
      :password_properties, :password_complex?,
      :password_complexity_inclusion_regexp,
      :lockout_duration, :lockout_threshold, :lockout_observation_window,
      :to => :root

    define_attribute_methods(
      # User attributes
      :account_name     => 'sAMAccountName',
      :email            => 'mail',
      :first_name       => 'givenName',
      :last_name        => 'sn',
      :display_name     => 'displayName',
      :room             => 'roomNumber',
      :avatar           => 'thumbnailPhoto', # binary string representation of a JPEG photo

      # organizationalPerson attributes
      :employee_id      => 'employeeID',
      :employee_type    => 'employeeType',
      :employee_number  => 'employeeNumber',
      :division         => 'division',

      :personal_email   => 'otherMailbox',   # E-Mail address (Others)
      :personal_mobile  => 'otherMobile',    # Mobile Phone (Others)
      :official_phone   => 'telephoneNumber',
      :official_mobile  => 'mobile',         # Official Mobile Phone
      :expires_at       => 'accountExpires',

      :member_of        => 'memberOf',

      :country_code     => 'c',
      :country_name     => 'co',
      :city             => 'l',
    )

    def initialize_from(entry, options)
      super
      return if persisted?

      @attributes['objectClass']          = %w( top person organizationalPerson user )

      @attributes['userAccountControl'] ||= '544' # Normal user + No password required
    end

    def attributes
      return super if persisted?

      @cn = name

      super.tap do |attrs|
        attrs['userPrincipalName'] ||= [ self.sAMAccountName, self.root.domain].join('@')
        attrs['displayName']       ||= name
        attrs['mail']              ||= attrs['userPrincipalName']
      end
    end

    def name
      @attributes['name'] || @attributes.values_at('givenName', 'sn').join(' ').presence
    end

    def avatar
      if avatar = self['thumbnailPhoto']
        Avatar.new(avatar, self.account_name)
      end
    end

    def principal
      self['userPrincipalName']
    end

    def expires_at
      AD.interval_to_time(self['accountExpires'])
    end

    def expires_at=(time)
      self['accountExpires'] = AD.time_to_interval(time)
    end

    def expires?
      ![0, 0x7FFFFFFFFFFFFFFF].include?(self['accountExpires'].to_i)
    end

    def active?
      !expires? || expires_at.future?
    end

    def valid_password?
      !password_expires? || password_expired?
    end

    def password_expires_at
      return unless password_expires?
      password_changed_at + root.max_password_age
    end

    def locked_out?
      # Unreliable.
      # account_flags & ADS_UF_LOCKOUT > 0
      !locked_out_at.nil?
    end

    def disabled?
      account_flags & ADS_UF_ACCOUNTDISABLE > 0
    end

    def password_expires?
      account_flags & ADS_UF_DONT_EXPIRE_PASSWD == 0
    end

    def password_expired?
      must_change_password? || (account_flags & ADS_UF_PASSWORD_EXPIRED > 0)
    end

    def can_change_password?
      account_flags & ADS_UF_PASSWD_CANT_CHANGE == 0
    end

    def must_change_password?
      self['pwdLastSet'] == '0' # Must change
    end

    def password_changed_at
      AD.interval_to_time(self['pwdLastSet'])
    end

    def password_complexity_exclusion_regexp
      root.password_complexity_exclusion_regexp(self)
    end

    def locked_out_at
      return if self['lockoutTime'].nil? || self['lockoutTime'] == '0' # Not Locked Out
      AD.interval_to_time(self['lockoutTime'])
    end

    def account_flags
      self['userAccountControl'].to_i
    end

    def failed_login_attempts
      self['badPwdCount'].to_i
    end

    def remaining_login_attempts
      lockout_threshold - failed_login_attempts
    end

    def last_failed_login
      AD.interval_to_time(self['badPasswordTime'])
    end

    # AD Constants
    ADS_UF_ACCOUNTDISABLE     = 0x2
    ADS_UF_LOCKOUT            = 0x10
    ADS_UF_PASSWD_CANT_CHANGE = 0x40
    ADS_UF_DONT_EXPIRE_PASSWD = 0x10000
    ADS_UF_PASSWORD_EXPIRED   = 0x800000

    def change_password!(old, new)
      success, message = self.class.change_password(self.dn, old, new)
      reload

      if success
        true
      else
        raise Error, "Password change failed: #{message}"
      end
    end

    def change_password(old, new)
      change_password!(old, new)
    rescue LDAP::Model::Error
      false
    end

    def reset_password!(new)
      success, message = self.class.reset_password(self.dn, new)
      reload

      if success
        true
      else
        raise Error, "Password reset failed: #{message}"
      end
    end

    def reset_password(new)
      reset_password!(new)
    rescue LDAP::Model::Error
      false
    end

    def unlock!
      success, message = self.class.unlock(self.dn)
      reload

      if success
        true
      else
        raise Error, "Account unlock failed: #{message}"
      end
    end

    def unlock
      unlock!
    rescue LDAP::Model::Error
      false
    end

    class << self
      # Password management
      #
      # http://msdn.microsoft.com/en-us/library/cc223248.aspx
      #
      # Please note that for password change and reset to work,
      # LDAP must be accessed over SSL. The IFAD *.ifad.org cert
      # works fine, as long as it is installed in the NTDS Service
      # certificate store.
      #
      # http://technet.microsoft.com/en-us/library/dd941846(WS.10).aspx
      #
      # Then, make sure to configure encryption: :simple_tls in ldap.yml
      # and to connect to port 636.
      #
      def change_password(dn, old, new)
        modify(dn, 'Change Password', [
          [:delete, :unicodePwd, wrap_passwd_for_ad(old)],
          [:add,    :unicodePwd, wrap_passwd_for_ad(new)]
        ])
      end

      def reset_password(dn, new)
        modify(dn, 'Reset Password', [
          [:replace, :unicodePwd, wrap_passwd_for_ad(new)]
        ])
      end

      # Account unlock
      #
      def unlock(dn)
        modify(dn, 'Unlock Account', [[:replace, :lockoutTime, '0']])
      end

      private
        def wrap_passwd_for_ad(pwd)
          ['"', pwd, '"'].join.encode('utf-16le').force_encoding('binary')
        end

    end
  end
end
