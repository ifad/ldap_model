require 'active_support/core_ext/time/zones'

module LDAP::Model
  module AD

    autoload :Person, 'ldap/model/ad/person'
    autoload :Root,   'ldap/model/ad/root'

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
      ((utc.now.to_f - EPOCH_OFFSET) * INTERVAL_SEC_RATIO).to_i
    end

    def self.at(timestamp)
      utc.at(timestamp / INTERVAL_SEC_RATIO + EPOCH_OFFSET).localtime
    end

    def self.utc
      @utc ||= Time.find_zone('UTC')
    end

  end
end
