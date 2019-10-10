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

  # OpenCensus implementation of counters.
  class OpenCensusCounter < BaseCounter
    def initialize(recorder, measure)
      raise ArgumentError, 'measure must not be nil' if measure.nil?
      @recorder = recorder
      @measure = measure
    end

    def increment(by: 1, labels: {})
      tag_map = OpenCensus::Tags::TagMap.new(
        labels.transform_keys(&:to_s).transform_values(&:to_s))
      @recorder.record(@measure.create_measurement(value: by, tags: tag_map))
    end
  end

  # Base class for the monitoring registry.
  class BaseMonitoringRegistry
    def initialize(_project_id, _monitored_resource)
    end

    def counter(_name, _labels, _docstring)
      nil
    end

    def export
      nil
    end
  end

  # Prometheus implementation of the monitoring registry, that uses the default
  # registry in the official Prometheus client library.
  class PrometheusMonitoringRegistry < BaseMonitoringRegistry
    def self.name
      'prometheus'
    end

    def initialize(_project_id, _monitored_resource)
      super
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

  # OpenCensus implementation of the monitoring registry.
  class OpenCensusMonitoringRegistry < BaseMonitoringRegistry
    def self.name
      'opencensus'
    end

    def initialize(project_id, monitored_resource)
      super
      require 'opencensus'
      require 'opencensus-stackdriver'
      @log = $log # rubocop:disable Style/GlobalVars
      @recorder = OpenCensus::Stats.ensure_recorder
      @exporter = OpenCensus::Stats::Exporters::Stackdriver.new(
        project_id: project_id,
        metric_prefix: 'agent.googleapis.com/agent',
        resource_type: monitored_resource.type,
        resource_labels: monitored_resource.labels)
      OpenCensus.configure do |c|
        c.stats.exporter = @exporter
      end
      @log.debug "OpenCensus config=#{OpenCensus.config}"
    end

    def counter(name, labels, docstring)
      name = OpenCensusMonitoringRegistry.translate_metric_name(name)
      measure = OpenCensus::Stats::MeasureRegistry.get(name)
      if measure.nil?
        measure = OpenCensus::Stats.create_measure_int(
          name: name,
          unit: OpenCensus::Stats::Measure::UNIT_NONE,
          description: docstring
        )
      end
      OpenCensus::Stats.create_and_register_view(
        name: name,
        measure: measure,
        aggregation: OpenCensus::Stats.create_sum_aggregation,
        description: docstring,
        columns: labels.map(&:to_s)
      )
      OpenCensusCounter.new(@recorder, measure)
    end

    def export
      @exporter.export @recorder.views_data
    end

    class << self
      # Translate the internal metrics to the curated metrics in Stackdriver.
      # The Prometheus metrics are collected by Google Kubernetes Engine's
      # monitoring, so we can't redefine them.
      def translate_metric_name(name)
        case name
        when :stackdriver_successful_requests_count,
             :stackdriver_failed_requests_count
          :request_count
        when :stackdriver_ingested_entries_count,
             :stackdriver_dropped_entries_count
          :log_entry_count
        when :stackdriver_retried_entries_count
          :log_entry_retry_count
        else
          name
        end
      end
    end
  end

  # Factory that is used to create a monitoring registry based on
  # the monitoring solution name.
  class MonitoringRegistryFactory
    @known_registry_types = {
      PrometheusMonitoringRegistry.name =>
        PrometheusMonitoringRegistry,
      OpenCensusMonitoringRegistry.name =>
        OpenCensusMonitoringRegistry
    }

    def self.supports_monitoring_type(name)
      @known_registry_types.key?(name)
    end

    def self.create(name, project_id, monitored_resource)
      registry = @known_registry_types[name] || BaseMonitoringRegistry
      registry.new(project_id, monitored_resource)
    end
  end
end
