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
    def increment(*)
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
    def initialize(recorder, measure, translator)
      raise ArgumentError, 'measure must not be nil' if measure.nil?
      @recorder = recorder
      @measure = measure
      @translator = translator
    end

    def increment(by: 1, labels: {})
      labels = @translator.translate_labels(labels)
      tag_map = OpenCensus::Tags::TagMap.new(
        labels.map { |k, v| [k.to_s, v.to_s] }.to_h)
      @recorder.record(@measure.create_measurement(value: by, tags: tag_map))
    end
  end

  # Base class for the monitoring registry.
  class BaseMonitoringRegistry
    def initialize(_project_id, _monitored_resource, _gcm_service_address)
    end

    def counter(_name, _labels, _docstring, _prefix = None)
      BaseCounter.new
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

    def initialize(_project_id, _monitored_resource, _gcm_service_address)
      super
      require 'prometheus/client'
      @registry = Prometheus::Client.registry
    end

    # Exception-driven behavior to avoid synchronization errors.
    def counter(name, _labels, docstring, _prefix = None)
      # When we upgrade to Prometheus client 0.10.0 or higher, pass the
      # labels in the metric constructor. The 'labels' field in
      # Prometheus client 0.9.0 has a different function and will not
      # work as intended.
      return PrometheusCounter.new(@registry.counter(name, docstring))
    rescue Prometheus::Client::Registry::AlreadyRegisteredError
      return PrometheusCounter.new(@registry.get(name))
    end
  end

  # OpenCensus implementation of the monitoring registry.
  class OpenCensusMonitoringRegistry < BaseMonitoringRegistry
    DEFAULT_PREFIX = 'agent.googleapis.com/agent'.freeze

    def self.name
      'opencensus'
    end

    def initialize(project_id, monitored_resource, gcm_service_address)
      super
      require 'opencensus'
      require 'opencensus-stackdriver'
      @log = $log # rubocop:disable Style/GlobalVars
      @project_id = project_id
      @monitored_resource = monitored_resource
      @gcm_service_address = gcm_service_address
      @recorders = { DEFAULT_PREFIX => OpenCensus::Stats.ensure_recorder }
      @exporters = {
        DEFAULT_PREFIX =>
          OpenCensus::Stats::Exporters::Stackdriver.new(
            project_id: project_id,
            metric_prefix: DEFAULT_PREFIX,
            resource_type: monitored_resource.type,
            resource_labels: monitored_resource.labels,
            gcm_service_address: gcm_service_address
          )
      }
      OpenCensus.configure do |c|
        c.stats.exporter = @exporters[DEFAULT_PREFIX]
      end
      @log.debug "OpenCensus config=#{OpenCensus.config}"
    end

    def counter(name, labels, docstring, prefix = DEFAULT_PREFIX)
      translator = MetricTranslator.new(name, labels)
      measure = OpenCensus::Stats::MeasureRegistry.get(translator.name)
      if measure.nil?
        measure = OpenCensus::Stats.create_measure_int(
          name: translator.name,
          unit: OpenCensus::Stats::Measure::UNIT_NONE,
          description: docstring
        )
      end
      unless @exporters.keys.include?(prefix)
        @recorders[prefix] = OpenCensus::Stats.ensure_recorder
        @exporters[prefix] = \
          OpenCensus::Stats::Exporters::Stackdriver.new(
            project_id: @project_id,
            metric_prefix: prefix,
            resource_type: @monitored_resource.type,
            resource_labels: @monitored_resource.labels,
            gcm_service_address: @gcm_service_address
          )
      end
      OpenCensus::Stats.create_and_register_view(
        name: translator.name,
        measure: measure,
        aggregation: OpenCensus::Stats.create_sum_aggregation,
        description: docstring,
        columns: translator.view_labels.map(&:to_s)
      )
      OpenCensusCounter.new(@recorders[prefix], measure, translator)
    rescue StandardError => e
      @log.warn "Failed to count metrics for #{name}.", error: e
      raise e
    end

    def export
      @exporters.keys.each do |prefix|
        @exporters[prefix].export @recorders[prefix].views_data
      end
    rescue StandardError => e
      @log.warn 'Failed to export some metrics.', error: e
      raise e
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

    def self.create(name, project_id, monitored_resource, gcm_service_address)
      registry = @known_registry_types[name] || BaseMonitoringRegistry
      registry.new(project_id, monitored_resource, gcm_service_address)
    end
  end

  # Translate the internal metrics to the curated metrics in Stackdriver.  The
  # Prometheus metrics are collected by Google Kubernetes Engine's monitoring,
  # so we can't redefine them.
  # Avoid this mechanism for new metrics by defining them in their final form,
  # so they don't need translation.
  class MetricTranslator
    attr_reader :name
    attr_reader :view_labels

    def initialize(name, metric_labels)
      @legacy = true
      case name
      when :stackdriver_successful_requests_count,
           :stackdriver_failed_requests_count
        @name = :request_count
      when :stackdriver_ingested_entries_count,
           :stackdriver_dropped_entries_count
        @name = :log_entry_count
      when :stackdriver_retried_entries_count
        @name = :log_entry_retry_count
      else
        @name = name
        @legacy = false
      end
      # Collapsed from [:response_code, :grpc]
      @view_labels = @legacy ? [:response_code] : metric_labels
    end

    def translate_labels(labels)
      return labels unless @legacy
      translation = { code: :response_code, grpc: :grpc }
      labels.map { |k, v| [translation[k], v] }.to_h
    end
  end
end
