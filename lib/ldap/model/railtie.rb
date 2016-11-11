module LDAP::Model
  class Railtie < ::Rails::Railtie
    console do |app|
      LDAP::Model::Base.logger = Logger.new(STDERR)
    end

    initializer 'ldap_model.logger' do
      LDAP::Model::Base.logger ||= ::Rails.logger
    end

    initializer 'ldap_model.active_record' do
      ActiveSupport.on_load(:active_record) do
        extend LDAP::Model::ActiveRecord
      end
    end

    initializer 'ldap_model.log_runtime' do
      LDAP::Model::Instrumentation::LogSubscriber.attach_to :ldap

      ActiveSupport.on_load(:action_controller) do
        include LDAP::Model::Instrumentation::ControllerRuntime
      end
    end

    # We do not connect automatically on the test environment,
    # to allow an application to mock everything out in tests.
    #
    initializer 'ldap_model.connect' do
      # conf = Pathname('config/ldap.yml')

      # begin
      #   conf = YAML.load(conf.read).fetch(Rails.env)
      #   LDAP::Model::Base.establish_connection(conf)
      # rescue => e
      #   if Rails.env.test?
      #     $stderr.puts "** LDAP: connection disabled (#{conf}: #{e.to_s})."
      #     $stderr.puts "** To test LDAP integration, define a valid `test' environment."
      #     LDAP::Model::ActiveRecord.disable!

      #   elsif e.is_a?(Errno::ENOENT)
      #     raise "LDAP configuration is missing, please create #{conf}"
      #   elsif e.is_a?(KeyError)
      #     raise "LDAP configuration for environment `#{Rails.env}' was not found in #{conf}"
      #   else
      #     raise
      #   end
      # end
    end

    config.after_initialize do
      if defined?(Hirb)
        require 'ldap/model/hirb'
      end
    end
  end
end
