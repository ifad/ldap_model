module LDAP::Model
  module AD

    # Difference in seconds between the UNIX Epoch (1970-01-01)
    # and the Active Directory Epoch (1601-01-01)
    EPOCH_OFFSET = 11644477200
    def self.now
      (Time.now.to_i + EPOCH_OFFSET) * 10_000_000
    end

    # number of nanosec / 100, i.e. 10 times the number of microsec,
    # divide by 10_000_000 so it becomes number of seconds
    def self.at(timestamp)
      Time.at(timestamp / 10_000_000 - EPOCH_OFFSET)
    end

  end
end
