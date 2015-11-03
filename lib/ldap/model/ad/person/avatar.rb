module LDAP::Model

  # Carrierwave-Friendly wrapper
  #
  class AD::Person::Avatar < StringIO
    def initialize(data, name, format = 'jpg')
      super(data.to_s, 'r')
      @name = [name, format].join('.')
    end

    def read
      rewind
      super
    end

    def sha1
      Digest::SHA1.hexdigest(self.read.to_s)
    end

    def blank?
      size.zero?
    end

    attr_reader :name
    alias :path :name
  end

end
