require 'active_support/core_ext/time/zones'

module LDAP::Model
  module AD

    autoload :Group,      'ldap/model/ad/group'
    autoload :Person,     'ldap/model/ad/person'
    autoload :Root,       'ldap/model/ad/root'

    autoload :Timestamps, 'ldap/model/ad/timestamps'

    # Difference in seconds between the UNIX Epoch (1970-01-01)
    # and the Active Directory Epoch (1601-01-01)
    EPOCH_OFFSET = Time.utc(1601).to_i

    # AD time granularity is 100 nanosec.
    # 1 sec = 10_000_000 nanosec^-2.
    #
    # So, conversion:
    #
    #   seconds * INTERVAL_SEC_RATIO = AD interval
    #   AD interval / INTERVAL_SEC_RATIO = seconds
    #
    INTERVAL_SEC_RATIO = 10_000_000.0

    def self.now
      time_to_interval(utc.now)
    end

    def self.time_to_interval(time)
      ((time.utc.to_f - EPOCH_OFFSET) * INTERVAL_SEC_RATIO).to_i
    end

    def self.interval_to_time(interval)
      utc.at(interval.to_f / INTERVAL_SEC_RATIO + EPOCH_OFFSET).localtime
    end

    # http://msdn.microsoft.com/en-us/library/windows/desktop/ms684436(v=vs.85).aspx
    def self.asn1_to_time(asn1)
      if match = asn1.match(/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.0Z/)
        Time.utc(*match.captures.map(&:to_i)).localtime
      end
    end

    # http://msdn.microsoft.com/en-us/library/windows/desktop/ms684426(v=vs.85).aspx
    def self.interval_to_secs(int_str)
      -(int_str.to_i / INTERVAL_SEC_RATIO).to_i
    end

    def self.utc
      @utc ||= Time.find_zone('UTC')
    end

  end
end
