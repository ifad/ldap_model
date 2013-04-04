module LDAP::Model
  class AD::Person < Base

    string_attributes %w[
      accountExpires
      pwdLastSet
      userAccountControl
      badPwdCount
      badPasswordTime
    ]

    computed_attributes %w[
      active?
      extension
      expiration
      valid_password?
      locked_out?
      disabled?
    ]

    class << self

      def filter_only_person
	Net::LDAP::Filter.eq('objectClass', 'person')
      end

      def filter_active_person
	Net::LDAP::Filter.ge('accountExpires', AD.now.to_s)
      end

      # Find by sAMAccountName
      #
      def find_by_account(account_name)
	base.each do |branch|
	  result = find_one(base: branch, filter: Net::LDAP::Filter.eq('sAMAccountName', account_name))
	  return result if result
	end
	nil
      end

    end

    def expiration
      AD.at(self['accountExpires'].to_i).to_date
    end

    def active?
      expiration.future?
    end

    def valid_password?
      !password_expires? || password_expired?
    end

    def locked_out?
      account_flags & ADS_UF_LOCKOUT > 0
    end

    def disabled?
      account_flags & ADS_UF_ACCOUNTDISABLE > 0
    end

    def password_expires?
      account_flags & ADS_UF_DONT_EXPIRE_PASSWD == 0
    end

    def password_expired?
      account_flags & ADS_UF_PASSWORD_EXPIRED > 0
    end

    def can_change_password?
      account_flags & ADS_UF_PASSWD_CANT_CHANGE == 0
    end

    def password_last_set
      return if self['pwdLastSet'] == '0' # Must change
      AD.at(self['pwdLastSet'].to_i)
    end

    def account_flags
      self['userAccountControl'].to_i
    end

    def failed_login_attempts
      self['badPwdCount'].to_i
    end

    def last_failed_login
      AD.at(self['badPasswordTime'].to_i)
    end

    # AD Constants
    ADS_UF_ACCOUNTDISABLE     = 0x2
    ADS_UF_LOCKOUT            = 0x10
    ADS_UF_PASSWD_CANT_CHANGE = 0x40
    ADS_UF_DONT_EXPIRE_PASSWD = 0x10000
    ADS_UF_PASSWORD_EXPIRED   = 0x800000

    def change_password!(old, new)
      success, message = self.class.change_password(self.dn, old, new)
      if success
	reload
	true
      else
	raise Error, "Password change failed: #{message}"
      end
    end

    def change_password(old, new)
      change_password!(old, new) rescue false
    end

    def reset_password!(new)
      success, message = self.class.reset_password(self.dn, new)
      if success
	reload
	true
      else
	raise Error, "Password reset failed: #{message}"
      end
    end

    def reset_password(new)
      reset_password!(new) rescue false
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
	instrument(:update, :dn => dn, :changes => 'Change Password') do |event|

	  success = connection.modify(:dn => dn, :operations => [
	    [:delete, :unicodePwd, wrap_passwd_for_ad(old)],
	    [:add,    :unicodePwd, wrap_passwd_for_ad(new)]
	  ])
	  message = connection.get_operation_result.message

	  event.update(:success => success, :message => message)

	  [success, message]
	end
      end

      def reset_password(dn, new)
	instrument(:update, :dn => dn, :changes => 'Reset Password') do |event|
	  success = connection.modify(:dn => dn, :operations => [
	    [:replace, :unicodePwd, wrap_passwd_for_ad(new)]
	  ])
	  message = connection.get_operation_result.message

	  event.update(:success => success, :message => message)

	  [success, message]
	end
      end

      private
	def wrap_passwd_for_ad(pwd)
	  ['"', pwd, '"'].join.encode('utf-16le').force_encoding('binary')
	end

    end
  end
end
