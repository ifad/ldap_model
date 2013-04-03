module LDAP::Model
  class Railtie < ::Rails::Railtie
    console do |app|
      LDAP::Model::Base.logger = Logger.new(STDERR)
    end

    initializer 'ldap_model.logger' do
      LDAP::Model::Base.logger ||= ::Rails.logger
    end

    initializer 'ldap_model.active_record' do
      require 'ldap/model/active_record'
      ActiveSupport.on_load(:active_record) do
        extend LDAP::Model::ActiveRecord
      end
    end

    initializer 'ldap_model.log_runtime' do
      require 'ldap/model/instrumentation'
      LDAP::Model::Instrumentation::LogSubscriber.attach_to :ldap

      ActiveSupport.on_load(:action_controller) do
        include LDAP::Model::Instrumentation::ControllerRuntime
      end
    end

    initializer 'ldap_model.connect' do
      LDAP::Model::Base.establish_connection
    end

    config.after_initialize do
      if defined?(Hirb)
        require 'ldap/model/hirb'
      end
    end
  end
end
