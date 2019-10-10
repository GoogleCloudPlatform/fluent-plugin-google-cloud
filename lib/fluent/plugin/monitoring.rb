# Copyright 2017 Google Inc. All rights reserved.
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

module Monitoring
  # Base class for the counter.
  class BaseCounter
    def increment(_labels, _count)
      nil
    end
  end

  # Prometheus implementation of counters.
  class PrometheusCounter < BaseCounter
    def initialize(prometheus_counter)
      @counter = prometheus_counter
    end

    def increment(by: 1, labels: {})
      @counter.increment(labels, by)
    end
  end

  # Base class for the monitoring registry.
  class BaseMonitoringRegistry
    def counter(_name, _labels, _docstring)
      nil
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

    # Exception-driven behavior to avoid synchronization errors.
    def counter(name, labels, docstring)
      return PrometheusCounter.new(@registry.counter(name, docstring, labels))
    rescue Prometheus::Client::Registry::AlreadyRegisteredError
      return PrometheusCounter.new(@registry.get(name))
    end
  end

  # Factory that is used to create a monitoring registry based on
  # the monitoring solution name.
  class MonitoringRegistryFactory
    @known_registry_types = {
      PrometheusMonitoringRegistry.name =>
        PrometheusMonitoringRegistry
    }

    def self.supports_monitoring_type(name)
      @known_registry_types.key?(name)
    end

    def self.create(name)
      (@known_registry_types[name] || BaseMonitoringRegistry).new
    end
  end
end
