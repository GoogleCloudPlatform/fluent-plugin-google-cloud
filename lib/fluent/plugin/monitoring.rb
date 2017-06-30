# Copyright 2014 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
require 'grpc'
require 'json'
require 'open-uri'
require 'socket'
require 'time'
require 'yaml'
require 'google/apis'
require 'google/apis/logging_v2beta1'
require 'google/logging/v2/logging_pb'
require 'google/logging/v2/logging_services_pb'
require 'google/logging/v2/log_entry_pb'
require 'googleauth'

module Monitoring
  # Factory that is used to create a monitoring registry based on
  # the monitoring solution name
  class MonitoringRegistryFactory
    def self.create(name)
      case name
      when PrometheusMonitoringRegistry.name
        return PrometheusMonitoringRegistry.new
      else
        return BaseMonitoringRegistry.new
      end
    end
  end

  # Base class for the monitoring registry
  class BaseMonitoringRegistry
    def counter(_name, _desc)
      _undefined
    end
  end

  # Prometheus implementation of the monitoring registry, that uses the default
  # registry in the official Prometheus client library.
  class PrometheusMonitoringRegistry < BaseMonitoringRegistry
    def self.name
      'prometheus'
    end

    def initialize
      require 'prometheus/client'
      @registry = Prometheus::Client.registry
    end

    # Exception-driven behavior to avoid synchronization errors
    def counter(name, desc)
      return @registry.counter(name, desc)
    rescue Prometheus::Client::Registry::AlreadyRegisteredError
      return @registry.get(name)
    end
  end
end
