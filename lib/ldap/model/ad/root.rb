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
  end
end
