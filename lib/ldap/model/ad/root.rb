module LDAP::Model
  class AD::Root < Base
    base connection.base

    string_attributes [
      'name',

      # http://msdn.microsoft.com/en-us/library/windows/desktop/ms676863(v=vs.85).aspx
      #
      # The maximum amount of time, in 100-nanosecond intervals, a password is
      # valid. This value is stored as a large integer that represents the
      # number of 100-nanosecond intervals from the time the password was set
      # before the password expires.
      #
      'maxPwdAge',

      # http://msdn.microsoft.com/en-us/library/windows/desktop/ms677110(v=vs.85).aspx
      #
      # The minimum amount of time that a password is valid.
      #
      'minPwdAge',

      # http://msdn.microsoft.com/en-us/library/windows/desktop/ms677113(v=vs.85).aspx
      #
      # The minimum number of characters that a password must contain.
      #
      'minPwdLength',

      # http://msdn.microsoft.com/en-us/library/windows/desktop/ms679429(v=vs.85).aspx
      #
      # The number of old passwords to save.
      #
      'pwdHistoryLength',

      # http://msdn.microsoft.com/en-us/library/windows/desktop/ms679431(v=vs.85).aspx
      #
      # Password Properties. Part of Domain Policy. A bitfield to indicate
      # complexity and storage restrictions.
      #
      'pwdProperties',
    ]

    def self.find
      super(base.first)
    end

    # Returns the maximum password age in seconds
    #
    def max_password_age
      self['maxPwdAge'].to_i / AD::INTERVAL_SEC_RATIO
    end

    # Returns the minimum password age in seconds
    #
    def min_password_age
      self['minPwdAge'].to_i / AD::INTERVAL_SEC_RATIO
    end

    # Returns the minimum password length
    #
    def min_password_length
      self['minPwdLength'].to_i
    end

    # Returns the password history length
    #
    def password_history_length
      self['pwdHistoryLength'].to_i
    end

    # Returns an array of password properties
    #
    def password_properties
      bitmask = self['pwdProperties'].to_i

      [].tap do |ret|
        PASSWORD_PROPERTIES.each do |flag, descr|
          ret.push(descr) if bitmask & flag > 0
        end
      end
    end

    # http://msdn.microsoft.com/en-us/library/windows/desktop/aa375371(v=vs.85).aspx
    #
    DOMAIN_PASSWORD_COMPLEX         = 1
    DOMAIN_PASSWORD_NO_ANON_CHANGE  = 2
    DOMAIN_PASSWORD_NO_CLEAR_CHANGE = 4
    DOMAIN_LOCKOUT_ADMINS           = 8
    DOMAIN_PASSWORD_STORE_CLEARTEXT = 16
    DOMAIN_REFUSE_PASSWORD_CHANGE   = 32

    PASSWORD_PROPERTIES = {
      DOMAIN_PASSWORD_COMPLEX =>
        %[The password must have a mix of at least two: Uppercase characters, Lowercase characters, Numerals],

      DOMAIN_PASSWORD_NO_ANON_CHANGE =>
        %[The password cannot be changed without logging on. Otherwise, if your password has expired, you can change your password and then log on.],

      DOMAIN_PASSWORD_NO_CLEAR_CHANGE =>
        %[Forces the client to use a protocol that does not allow the domain controller to get the plaintext password.],

      DOMAIN_LOCKOUT_ADMINS =>
        %[Allows the built-in administrator account to be locked out from network logons.],

      DOMAIN_PASSWORD_STORE_CLEARTEXT =>
        %[The directory service is storing a plaintext password for all users instead of a hash function of the password.],

      DOMAIN_REFUSE_PASSWORD_CHANGE =>
        %[Removes the requirement that the machine account password be automatically changed every week.]
    }
  end
end
