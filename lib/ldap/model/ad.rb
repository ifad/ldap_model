require 'active_support/core_ext/time/zones'

module LDAP::Model
  module AD

    autoload :Person, 'ldap/model/ad/person'

    # Difference in seconds between the UNIX Epoch (1970-01-01)
    # and the Active Directory Epoch (1601-01-01)
    EPOCH_OFFSET = Time.utc(1601).to_i
    def self.now
      ((utc.now.to_f - EPOCH_OFFSET) * 10_000_000).to_i
    end

    # number of nanosec / 100, i.e. 10 times the number of microsec,
    # divide by 10_000_000 so it becomes number of seconds
    def self.at(timestamp)
      utc.at(timestamp / 10_000_000.0 + EPOCH_OFFSET).localtime
    end

    def self.utc
      @utc ||= Time.find_zone('UTC')
    end

  end
end
