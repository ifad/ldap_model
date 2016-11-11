module LDAP::Model
  class AD::Root < Base
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

      # http://msdn.microsoft.com/en-us/library/windows/desktop/ms676840(v=vs.85).aspx
      #
      # The amount of time that an account is locked due to the
      # Lockout-Threshold being exceeded. This value is stored as a large
      # integer that represents the negative of the number of 100-nanosecond
      # intervals from the time the Lockout-Threshold is exceeded that must
      # elapse before the account is unlocked.
      #
      'lockoutDuration',

      # http://msdn.microsoft.com/en-us/library/windows/desktop/ms676842(v=vs.85).aspx
      #
      # The number of invalid logon attempts that are permitted before the
      # account is locked out.
      #
      'lockoutThreshold',

      # http://msdn.microsoft.com/en-us/library/windows/desktop/ms676841(v=vs.85).aspx
      #
      # The range of time in which the system increments the incorrect logon
      # count.
      #
      'lockOutObservationWindow',
    ]

    def self.find
      super(base.first)
    end

    # Returns the DNS domain name
    #
    def domain
      dn.scan(/dc=(\w+)/i).flatten.join('.').downcase
    end

    # Returns the account lockout duration in seconds
    #
    def lockout_duration
      AD.interval_to_secs(self['lockoutDuration'])
    end

    # Returns the amount of failed logins before an account is locked out
    #
    def lockout_threshold
      self['lockoutThreshold'].to_i
    end

    # Returns the time range in seconds in which the system increments the
    # incorrect logon count
    #
    def lockout_observation_window
      AD.interval_to_secs(self['lockOutObservationWindow'])
    end

    # Returns the maximum password age in seconds
    #
    def max_password_age
      AD.interval_to_secs(self['maxPwdAge'])
    end

    # Returns the minimum password age in seconds
    #
    def min_password_age
      AD.interval_to_secs(self['minPwdAge'])
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
      bitmask = self.password_properties_bitmask

      [].tap do |ret|
        PASSWORD_PROPERTIES.each do |flag, descr|
          ret.push(descr) if bitmask & flag > 0
        end
      end
    end

    # Returns the password properties bitmask
    #
    def password_properties_bitmask
      self['pwdProperties'].to_i
    end

    # Returns true if the policy requires a 'complex' password
    # http://technet.microsoft.com/en-us/library/cc786468(v=ws.10).aspx
    #
    def password_complex?
      self.password_properties_bitmask & DOMAIN_PASSWORD_COMPLEX > 0
    end

    # Returns a regexp for the given person such as if the
    # new password matches this regexp it is invalid.
    #
    # http://technet.microsoft.com/en-us/library/cc786468(v=ws.10).aspx
    #
    def password_complexity_exclusion_regexp(person)
      tokens = []

      # The samAccountName is checked in its entirety only to determine
      # whether it is part of the password. If the samAccountName is less
      # than three characters long, this check is skipped.
      #

      tokens << person.sAMAccountName if person.sAMAccountName.length >= 3

      # The displayName is parsed for delimiters: commas, periods, dashes
      # or hyphens, underscores, spaces, pound signs, and tabs. If any of
      # these delimiters are found, the displayName is split and all
      # parsed sections (tokens) are confirmed not to be included in the
      # password. Tokens that are less than three characters in length
      # are ignored, and substrings of the tokens are not checked.
      #
      tokens.concat person.displayName.split(/[\.\s,#_-]+/) #.scan(/\w+/)

      source = tokens.map! {|tok| "(?:#{Regexp.escape(tok)})"}.join('|')

      Regexp.compile source, Regexp::IGNORECASE
    end

    # Returns a regexp such as if the match fails, the new password is
    # invalid.
    #
    def password_complexity_inclusion_regexp
      # Passwords must contain characters from at least three of the
      # following four categories:
      #
      # - English uppercase alphabet characters (A–Z)
      # - English lowercase alphabet characters (a–z)
      # - Base 10 digits (0–9)
      # - Non-alphanumeric characters (~!@#$%^&*_-+=`|\(){}[]:;"'<>,.?/)
      #

      @complexity_re ||= begin
        classes = [
          '[A-Z]',
          '[a-z]',
          '[0-9]',
          '[~!@#$%^&*_+=`|\\(){}\[\]:;"\'<>,.?/-]'
        ]

        Regexp.compile classes
          .map {|c| ['(?:', c, ')'].join} # Wrap the char classes
          .permutation(classes.size - 1)  # Permutation
          .map {|g| g.join('.*?') }       # Other chars may appear in between
          .join('|')
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
