require 'active_support/log_subscriber'
require 'active_support/concern'
require 'active_support/core_ext/module/attr_internal'
require 'active_support/core_ext/module/delegation'

module LDAP::Model
  module Instrumentation

    # LogSubscriber to log LDAP request URLs and timings
    #
    # h/t https://gist.github.com/566725
    #
    class LogSubscriber < ActiveSupport::LogSubscriber
      def search(event)
        self.class.runtime += event.duration

        message  = ''
        message << " base: #{event.payload[:base]}" if event.payload.key?(:base)
        message << " scope: #{event.payload[:scope]}"
        message << " filter: #{event.payload[:filter]}"
        message << " => #{event.payload[:results]} results" if event.payload.key?(:results)

        info message, event.duration
      end

      def update(event)
        self.class.runtime += event.duration

        message  = " subject '#{event.payload[:dn]}'"
        message << " update #{event.payload[:changes].inspect}"
        message << " => #{event.payload[:success] ? 'SUCCESS' : 'FAILED'} " if event.payload.key?(:success)
        message << " (#{event.payload[:message]})" if event.payload.key?(:message)

        info message, event.duration
      end

      def connect(event)
        message  = "Connecting to server specified by #{event.payload[:config]}"
        message << " FAILED: #{event.payload[:exception].last}" if event.payload.key?(:exception)

        info message, event.duration
      end

      def bind(event)
        message  = "Authenticating to server as #{event.payload[:username]}"
        message << " => #{event.payload[:success] ? 'SUCCESS' : 'FAILED'}"

        info message, event.duration
      end

      def info(message, duration)
        super("  \033[1;33mLDAP\033[0m: %s (%.1fms)" % [ message, duration ])
      end

      class << self
        def runtime=(value)
          Thread.current[:ldap_runtime] = value
        end

        def runtime
          Thread.current[:ldap_runtime] ||= 0
        end

        def reset_runtime
          rt, self.runtime = runtime, 0
          rt
        end
      end
    end

    # ActionController Instrumentation to log time spent in LDAP
    # requests at the bottom of log messages.
    #
    module ControllerRuntime
      extend ActiveSupport::Concern

      attr_internal :ldap_runtime

      def append_info_to_payload(payload)
        super
        payload[:ldap_runtime] = (ldap_runtime || 0) + LDAP::Model::Instrumentation::LogSubscriber.reset_runtime
      end
      protected :append_info_to_payload

      def cleanup_view_runtime
        ldap_rt_before_render = LDAP::Model::Instrumentation::LogSubscriber.reset_runtime
        runtime = super
        ldap_rt_after_render = LDAP::Model::Instrumentation::LogSubscriber.reset_runtime
        self.ldap_runtime = ldap_rt_before_render + ldap_rt_after_render
        runtime - ldap_rt_after_render
      end
      protected :cleanup_view_runtime

      module ClassMethods
        def log_process_action(payload)
          messages, ldap_runtime = super, payload[:ldap_runtime]
          messages << ("LDAP: %.1fms" % ldap_runtime.to_f) if ldap_runtime
          messages
        end
      end

    end

  end
end
