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
require 'cgi'
require 'erb'
require 'grpc'
require 'json'
require 'open-uri'
require 'socket'
require 'time'
require 'yaml'
require 'google/apis'
require 'google/cloud/errors'
require 'google/apis/logging_v2'
require 'google/cloud/logging/v2'
require 'google/logging/v2/logging_pb'
require 'google/logging/v2/logging_services_pb'
require 'google/logging/v2/log_entry_pb'
require 'googleauth'

require_relative 'common'
require_relative 'monitoring'
require_relative 'statusz'

module Google
  module Protobuf
    # Alias the has_key? method to have the same interface as a regular map.
    class Map
      alias key? has_key?
      alias to_hash to_h
    end
  end
end

module Google
  module Auth
    # Disable gcloud lookup in googleauth to avoid picking up its project id.
    module CredentialsLoader
      # Set $VERBOSE to nil to mute the "already initialized constant" warnings.
      warn_level = $VERBOSE
      begin
        $VERBOSE = nil
        # These constants are used to invoke gcloud on Linux and Windows,
        # respectively. Ideally, we would have overridden
        # CredentialsLoader.load_gcloud_project_id, but we cannot catch it
        # before it's invoked via "require 'googleauth'". So we override the
        # constants instead.
        GCLOUD_POSIX_COMMAND = '/bin/true'.freeze
        GCLOUD_WINDOWS_COMMAND = 'cd .'.freeze
        GCLOUD_CONFIG_COMMAND = ''.freeze
      ensure
        $VERBOSE = warn_level
      end
    end
  end
end

# FluentLogger exposes the Fluent logger to the gRPC library.
module FluentLogger
  def logger
    $log # rubocop:disable Style/GlobalVars
  end
end

# Define a gRPC module-level logger method before grpc/logconfig.rb loads.
module GRPC
  extend FluentLogger
end

# Disable the nurse/strptime gem used by FluentD's TimeParser class in
# lib/fluent/time.rb. We found this gem to be slower than the builtin Ruby
# parser in recent versions of Ruby. Fortunately FluentD will fall back to the
# builtin parser.
require 'strptime'
# Dummy Strptime class.
class Strptime
  def self.new(_)
    # empty
  end
end

module Fluent
  # fluentd output plugin for the Stackdriver Logging API
  class GoogleCloudOutput < BufferedOutput
    # Constants for configuration.
    module ConfigConstants
      # Default values for JSON payload keys to set the "httpRequest",
      # "operation", "sourceLocation", "trace" fields in the LogEntry.
      DEFAULT_HTTP_REQUEST_KEY = 'httpRequest'.freeze
      DEFAULT_INSERT_ID_KEY = 'logging.googleapis.com/insertId'.freeze
      DEFAULT_LABELS_KEY = 'logging.googleapis.com/labels'.freeze
      DEFAULT_OPERATION_KEY = 'logging.googleapis.com/operation'.freeze
      DEFAULT_SOURCE_LOCATION_KEY =
        'logging.googleapis.com/sourceLocation'.freeze
      DEFAULT_SPAN_ID_KEY = 'logging.googleapis.com/spanId'.freeze
      DEFAULT_TRACE_KEY = 'logging.googleapis.com/trace'.freeze
      DEFAULT_TRACE_SAMPLED_KEY = 'logging.googleapis.com/trace_sampled'.freeze
    end

    # Internal constants.
    module InternalConstants
      CREDENTIALS_PATH_ENV_VAR = 'GOOGLE_APPLICATION_CREDENTIALS'.freeze
      DEFAULT_LOGGING_API_URL = 'https://logging.googleapis.com'.freeze

      # The label name of local_resource_id in the json payload. When a record
      # has this field in the payload, we will use the value to retrieve
      # monitored resource from Stackdriver Metadata agent.
      LOCAL_RESOURCE_ID_KEY = 'logging.googleapis.com/local_resource_id'.freeze

      # The regexp matches stackdriver trace id format: 32-byte hex string.
      # The format is documented in
      # https://cloud.google.com/trace/docs/reference/v2/rpc/google.devtools.cloudtrace.v1#trace
      STACKDRIVER_TRACE_ID_REGEXP = Regexp.new('^\h{32}$').freeze

      # Map from each field name under LogEntry to corresponding variables
      # required to perform field value extraction from the log record.
      LOG_ENTRY_FIELDS_MAP = {
        'http_request' => [
          # The config to specify label name for field extraction from record.
          '@http_request_key',
          # Map from subfields' names to their types.
          [
            # subfield key in the payload, destination key, cast lambda (opt)
            %w[cacheFillBytes cache_fill_bytes parse_int],
            %w[cacheHit cache_hit parse_bool],
            %w[cacheLookup cache_lookup parse_bool],
            %w[cacheValidatedWithOriginServer
               cache_validated_with_origin_server parse_bool],
            %w[latency latency parse_latency],
            %w[protocol protocol parse_string],
            %w[referer referer parse_string],
            %w[remoteIp remote_ip parse_string],
            %w[responseSize response_size parse_int],
            %w[requestMethod request_method parse_string],
            %w[requestSize request_size parse_int],
            %w[requestUrl request_url parse_string],
            %w[serverIp server_ip parse_string],
            %w[status status parse_int],
            %w[userAgent user_agent parse_string]
          ],
          # The grpc version class name.
          'Google::Cloud::Logging::Type::HttpRequest',
          # The non-grpc version class name.
          'Google::Apis::LoggingV2::HttpRequest'
        ],
        'operation' => [
          '@operation_key',
          [
            %w[id id parse_string],
            %w[producer producer parse_string],
            %w[first first parse_bool],
            %w[last last parse_bool]
          ],
          'Google::Cloud::Logging::V2::LogEntryOperation',
          'Google::Apis::LoggingV2::LogEntryOperation'
        ],
        'source_location' => [
          '@source_location_key',
          [
            %w[file file parse_string],
            %w[function function parse_string],
            %w[line line parse_int]
          ],
          'Google::Cloud::Logging::V2::LogEntrySourceLocation',
          'Google::Apis::LoggingV2::LogEntrySourceLocation'
        ]
      }.freeze

      # The name of the WriteLogEntriesPartialErrors field in the error details.
      PARTIAL_ERROR_FIELD =
        'type.googleapis.com/google.logging.v2.WriteLogEntriesPartialErrors' \
        .freeze
    end

    include Common::ServiceConstants
    include self::ConfigConstants
    include self::InternalConstants

    Fluent::Plugin.register_output('google_cloud', self)

    helpers :server, :timer

    PLUGIN_NAME = 'Fluentd Google Cloud Logging plugin'.freeze

    # Follows semver.org format.
    PLUGIN_VERSION = begin
      # Extract plugin version from file path.
      match_data = __FILE__.match(
        %r{fluent-plugin-google-cloud-(?<version>[^/]*)/}
      )
      if match_data
        match_data['version']
      else
        # Extract plugin version by finding the spec this file was loaded from.
        dependency = Gem::Dependency.new('fluent-plugin-google-cloud')
        all_specs, = Gem::SpecFetcher.fetcher.spec_for_dependency(dependency)
        matching_version, = all_specs.grep(
          proc { |spec,| __FILE__.include?(spec.full_gem_path) }
        ) do |spec,|
          spec.version.to_s
        end
        # If no matching version was found, return a valid but obviously wrong
        # value.
        matching_version || '0.0.0-unknown'
      end
    end.freeze

    # Disable this warning to conform to fluentd config_param conventions.
    # rubocop:disable Style/HashSyntax

    # Specify project/instance metadata.
    #
    # project_id, zone, and vm_id are required to have valid values, which
    # can be obtained from the metadata service or set explicitly.
    # Otherwise, the plugin will fail to initialize.
    #
    # Note that while 'project id' properly refers to the alphanumeric name
    # of the project, the logging service will also accept the project number,
    # so either one is acceptable in this context.
    #
    # Whether to attempt to obtain metadata from the local metadata service.
    # It is safe to specify 'true' even on platforms with no metadata service.
    config_param :use_metadata_service, :bool, :default => true
    # A compatibility option to enable the legacy behavior of setting the AWS
    # location to the availability zone rather than the region.
    config_param :use_aws_availability_zone, :bool, :default => true
    # These parameters override any values obtained from the metadata service.
    config_param :project_id, :string, :default => nil
    config_param :zone, :string, :default => nil
    config_param :vm_id, :string, :default => nil
    config_param :vm_name, :string, :default => nil
    # Kubernetes-specific parameters, only used to override these values in
    # the fallback path when the metadata agent is temporarily unavailable.
    # They have to match the configuration of the metadata agent.
    config_param :k8s_cluster_name, :string, :default => nil
    config_param :k8s_cluster_location, :string, :default => nil

    # Map keys from a JSON payload to corresponding LogEntry fields.
    config_param :http_request_key, :string, :default =>
      DEFAULT_HTTP_REQUEST_KEY
    config_param :insert_id_key, :string, :default => DEFAULT_INSERT_ID_KEY
    config_param :labels_key, :string, :default => DEFAULT_LABELS_KEY
    config_param :operation_key, :string, :default => DEFAULT_OPERATION_KEY
    config_param :source_location_key, :string, :default =>
      DEFAULT_SOURCE_LOCATION_KEY
    config_param :span_id_key, :string, :default => DEFAULT_SPAN_ID_KEY
    config_param :trace_key, :string, :default => DEFAULT_TRACE_KEY
    config_param :trace_sampled_key, :string, :default =>
      DEFAULT_TRACE_SAMPLED_KEY

    # Whether to try to detect if the record is a text log entry with JSON
    # content that needs to be parsed.
    config_param :detect_json, :bool, :default => false
    # TODO(igorpeshansky): Add a parameter for the text field in the payload.

    # Whether to try to detect if the VM is owned by a "subservice" such as App
    # Engine of Kubernetes, rather than just associating the logs with the
    # compute service of the platform. This currently only has any effect when
    # running on GCE.
    #
    # The initial motivation for this is to separate out Kubernetes node
    # component (Kubelet, etc.) logs from container logs.
    config_param :detect_subservice, :bool, :default => true
    # The subservice_name overrides the subservice detection, if provided.
    config_param :subservice_name, :string, :default => nil

    # Whether to reject log entries with invalid tags. If this option is set to
    # false, tags will be made valid by converting any non-string tag to a
    # string, and sanitizing any non-utf8 or other invalid characters.
    config_param :require_valid_tags, :bool, :default => false

    # The regular expression to use on Kubernetes logs to extract some basic
    # information about the log source. The regexp must contain capture groups
    # for pod_name, namespace_name, and container_name.
    config_param :kubernetes_tag_regexp, :string, :default =>
      '\.(?<pod_name>[^_]+)_(?<namespace_name>[^_]+)_(?<container_name>.+)$'

    # label_map (specified as a JSON object) is an unordered set of fluent
    # field names whose values are sent as labels rather than as part of the
    # struct payload.
    #
    # Each entry in the map is a {"field_name": "label_name"} pair.  When
    # the "field_name" (as parsed by the input plugin) is encountered, a label
    # with the corresponding "label_name" is added to the log entry.  The
    # value of the field is used as the value of the label.
    #
    # The map gives the user additional flexibility in specifying label
    # names, including the ability to use characters which would not be
    # legal as part of fluent field names.
    #
    # Example:
    #   label_map {
    #     "field_name_1": "sent_label_name_1",
    #     "field_name_2": "some.prefix/sent_label_name_2"
    #   }
    config_param :label_map, :hash, :default => nil

    # labels (specified as a JSON object) is a set of custom labels
    # provided at configuration time. It allows users to inject extra
    # environmental information into every message or to customize
    # labels otherwise detected automatically.
    #
    # Each entry in the map is a {"label_name": "label_value"} pair.
    #
    # Example:
    #   labels {
    #     "label_name_1": "label_value_1",
    #     "label_name_2": "label_value_2"
    #   }
    config_param :labels, :hash, :default => nil

    # Whether to use gRPC instead of REST/JSON to communicate to the
    # Stackdriver Logging API.
    config_param :use_grpc, :bool, :default => false

    # Whether to enable gRPC compression when communicating with the Stackdriver
    # Logging API. Only used if 'use_grpc' is set to true.
    config_param :grpc_compression_algorithm, :enum,
                 list: %i[none gzip],
                 :default => nil

    # Whether valid entries should be written even if some other entries fail
    # due to INVALID_ARGUMENT or PERMISSION_DENIED errors when communicating to
    # the Stackdriver Logging API. This flag is no longer used, and is kept for
    # backwards compatibility, partial_success is enabled for all requests.
    # TODO: Breaking change. Remove this flag in Logging Agent 2.0.0 release.
    config_param :partial_success, :bool,
                 :default => true,
                 :skip_accessor => true,
                 :deprecated => 'This feature is permanently enabled'

    # Whether to allow non-UTF-8 characters in user logs. If set to true, any
    # non-UTF-8 character would be replaced by the string specified by
    # 'non_utf8_replacement_string'. If set to false, any non-UTF-8 character
    # would trigger the plugin to error out.
    config_param :coerce_to_utf8, :bool, :default => true

    # If 'coerce_to_utf8' is set to true, any non-UTF-8 character would be
    # replaced by the string specified here.
    config_param :non_utf8_replacement_string, :string, :default => ' '

    # DEPRECATED: The following parameters, if present in the config
    # indicate that the plugin configuration must be updated.
    config_param :auth_method, :string, :default => nil
    config_param :private_key_email, :string, :default => nil
    config_param :private_key_path, :string, :default => nil
    config_param :private_key_passphrase, :string,
                 :default => nil,
                 :secret => true

    # The URL of Stackdriver Logging API. Right now this only works with the
    # gRPC path (use_grpc = true). An unsecured channel is used if the URL
    # scheme is 'http' instead of 'https'. One common use case of this config is
    # to provide a mocked / stubbed Logging API, e.g., http://localhost:52000.
    config_param :logging_api_url, :string, :default => DEFAULT_LOGGING_API_URL

    # Whether to collect metrics about the plugin usage. The mechanism for
    # collecting and exposing metrics is controlled by the monitoring_type
    # parameter.
    config_param :enable_monitoring, :bool, :default => false

    # What system to use when collecting metrics. Possible values are:
    #   - 'prometheus', in this case default registry in the Prometheus
    #     client library is used, without actually exposing the endpoint
    #     to serve metrics in the Prometheus format.
    #   - 'opencensus', in this case the OpenCensus implementation is
    #     used to send metrics directly to Google Cloud Monitoring.
    #   - any other value will result in the absence of metrics.
    config_param :monitoring_type, :string,
                 :default => Monitoring::PrometheusMonitoringRegistry.name

    # The monitored resource to use for OpenCensus metrics. Only valid
    # when monitoring_type is set to 'opencensus'. This value is a hash in
    # the form:
    # {"type":"gce_instance","labels":{"instance_id":"aaa","zone":"bbb"} (JSON)
    # or type:gce_instance,labels.instance_id:aaa,labels.zone:bbb (Hash)
    config_param :metrics_resource, :hash,
                 :symbolize_keys => true, :default => nil

    # Whether to call metadata agent to retrieve monitored resource. This flag
    # is kept for backwards compatibility, and is no longer used.
    # TODO: Breaking change. Remove this flag in Logging Agent 2.0.0 release.
    config_param :enable_metadata_agent, :bool,
                 :default => false,
                 :skip_accessor => true,
                 :deprecated => 'This feature is permanently disabled'

    # The URL of the Metadata Agent. This flag is kept for backwards
    # compatibility, and is no longer used.
    # TODO: Breaking change. Remove this flag in Logging Agent 2.0.0 release.
    config_param :metadata_agent_url, :string,
                 :default => nil,
                 :skip_accessor => true,
                 :deprecated => 'This feature is permanently disabled'

    # Whether to split log entries with different log tags into different
    # requests when talking to Stackdriver Logging API.
    config_param :split_logs_by_tag, :bool, :default => false

    # Whether to attempt adjusting invalid log entry timestamps.
    config_param :adjust_invalid_timestamps, :bool, :default => true

    # Whether to autoformat value of "logging.googleapis.com/trace" to
    # comply with Stackdriver Trace format
    # "projects/[PROJECT-ID]/traces/[TRACE-ID]" when setting
    # LogEntry.trace.
    config_param :autoformat_stackdriver_trace, :bool, :default => true

    # Port for web server that exposes a /statusz endpoint with
    # diagnostic information in HTML format.  If the value is 0,
    # the server is not created.
    config_param :statusz_port, :integer, :default => 0

    # Override for the Google Cloud Monitoring service hostname, or
    # `nil` to leave as the default.
    config_param :gcm_service_address, :string, :default => nil

    # rubocop:enable Style/HashSyntax

    # TODO: Add a log_name config option rather than just using the tag?

    # Expose attr_readers to make testing of metadata more direct than only
    # testing it indirectly through metadata sent with logs.
    attr_reader :project_id, :zone, :vm_id, :resource, :common_labels, :monitoring_resource

    def initialize
      super
      # use the global logger
      @log = $log # rubocop:disable Style/GlobalVars

      @failed_requests_count = nil
      @successful_requests_count = nil
      @dropped_entries_count = nil
      @ingested_entries_count = nil
      @retried_entries_count = nil

      @ok_code = nil
      @uptime_update_time = Time.now.to_i
    end

    def configure(conf)
      super

      # TODO(qingling128): Remove this warning after the support is added. Also
      # remove the comment in the description of this configuration.
      unless @logging_api_url == DEFAULT_LOGGING_API_URL || @use_grpc
        @log.warn 'Detected customized logging_api_url while use_grpc is not' \
                  ' enabled. Customized logging_api_url for the non-gRPC path' \
                  ' is not supported. The logging_api_url option will be' \
                  ' ignored.'
      end

      # Alert on old authentication configuration.
      unless @auth_method.nil? && @private_key_email.nil? &&
             @private_key_path.nil? && @private_key_passphrase.nil?
        extra = []
        extra << 'auth_method' unless @auth_method.nil?
        extra << 'private_key_email' unless @private_key_email.nil?
        extra << 'private_key_path' unless @private_key_path.nil?
        extra << 'private_key_passphrase' unless @private_key_passphrase.nil?

        raise Fluent::ConfigError,
              "#{PLUGIN_NAME} no longer supports auth_method.\n" \
              "Please remove configuration parameters: #{extra.join(' ')}"
      end

      set_regexp_patterns

      @utils = Common::Utils.new(@log)

      @platform = @utils.detect_platform(@use_metadata_service)

      # Treat an empty setting of the credentials file path environment variable
      # as unset. This way the googleauth lib could fetch the credentials
      # following the fallback path.
      ENV.delete(CREDENTIALS_PATH_ENV_VAR) if
        ENV[CREDENTIALS_PATH_ENV_VAR] == ''

      # Set required variables: @project_id, @vm_id, @vm_name and @zone.
      @project_id = @utils.get_project_id(@platform, @project_id)
      @vm_id = @utils.get_vm_id(@platform, @vm_id)
      @vm_name = @utils.get_vm_name(@vm_name)
      @zone = @utils.get_location(@platform, @zone, @use_aws_availability_zone)

      # All metadata parameters must now be set.
      @utils.check_required_metadata_variables(
        @platform, @project_id, @zone, @vm_id
      )

      # Retrieve monitored resource.
      # Fail over to retrieve monitored resource via the legacy path if we fail
      # to get it from Metadata Agent.
      @resource ||= @utils.determine_agent_level_monitored_resource_via_legacy(
        @platform, @subservice_name, @detect_subservice, @vm_id, @zone
      )

      if @metrics_resource
        unless @metrics_resource[:type].is_a?(String)
          raise Fluent::ConfigError,
                'metrics_resource.type must be a string:' \
                " #{@metrics_resource}."
        end
        if @metrics_resource.key?(:labels)
          unless @metrics_resource[:labels].is_a?(Hash)
            raise Fluent::ConfigError,
                  'metrics_resource.labels must be a hash:' \
                  " #{@metrics_resource}."
          end
          extra_keys = @metrics_resource.reject do |k, _|
            %i[type labels].include?(k)
          end
          unless extra_keys.empty?
            raise Fluent::ConfigError,
                  "metrics_resource has unrecognized keys: #{extra_keys.keys}."
          end
        else
          extra_keys = @metrics_resource.reject do |k, _|
            k == :type || k.to_s.start_with?('labels.')
          end
          unless extra_keys.empty?
            raise Fluent::ConfigError,
                  "metrics_resource has unrecognized keys: #{extra_keys.keys}."
          end
          # Transform the Hash form of the metrics_resource config if necessary.
          resource_type = @metrics_resource[:type]
          resource_labels = @metrics_resource.each_with_object({}) \
            do |(k, v), h|
              h[k.to_s.sub('labels.', '')] = v if k.to_s.start_with? 'labels.'
            end
          @metrics_resource = { type: resource_type, labels: resource_labels }
        end
      end

      # If monitoring is enabled, register metrics in the default registry
      # and store metric objects for future use.
      if @enable_monitoring
        unless Monitoring::MonitoringRegistryFactory.supports_monitoring_type(
          @monitoring_type
        )
          @log.warn "monitoring_type '#{@monitoring_type}' is unknown; "\
                    'there will be no metrics'
        end
        @monitoring_resource = if @metrics_resource
                                 @utils.create_monitored_resource(
                                   @metrics_resource[:type], @metrics_resource[:labels]
                                 )
                               else
                                 @resource
                               end
        @registry = Monitoring::MonitoringRegistryFactory
                    .create(@monitoring_type, @project_id,
                            @monitoring_resource, @gcm_service_address)
        # Export metrics every 60 seconds.
        timer_execute(:export_metrics, 60) { @registry.export }
        # Uptime should be a gauge, but the metric definition is a counter and
        # we can't change it.
        @uptime_metric = @registry.counter(
          :uptime, [:version], 'Uptime of Logging agent',
          'agent.googleapis.com/agent', 'CUMULATIVE'
        )
        update_uptime
        timer_execute(:update_uptime, 1) { update_uptime }
        @successful_requests_count = @registry.counter(
          :stackdriver_successful_requests_count,
          %i[grpc code],
          'A number of successful requests to the Stackdriver Logging API',
          'agent.googleapis.com/agent', 'CUMULATIVE'
        )
        @failed_requests_count = @registry.counter(
          :stackdriver_failed_requests_count,
          %i[grpc code],
          'A number of failed requests to the Stackdriver Logging '\
          'API, broken down by the error code',
          'agent.googleapis.com/agent', 'CUMULATIVE'
        )
        @ingested_entries_count = @registry.counter(
          :stackdriver_ingested_entries_count,
          %i[grpc code],
          'A number of log entries ingested by Stackdriver Logging',
          'agent.googleapis.com/agent', 'CUMULATIVE'
        )
        @dropped_entries_count = @registry.counter(
          :stackdriver_dropped_entries_count,
          %i[grpc code],
          'A number of log entries dropped by the Stackdriver output plugin',
          'agent.googleapis.com/agent', 'CUMULATIVE'
        )
        @retried_entries_count = @registry.counter(
          :stackdriver_retried_entries_count,
          %i[grpc code],
          'The number of log entries that failed to be ingested by '\
          'the Stackdriver output plugin due to a transient error '\
          'and were retried',
          'agent.googleapis.com/agent', 'CUMULATIVE'
        )
        @ok_code = @use_grpc ? GRPC::Core::StatusCodes::OK : 200
      end

      # Set regexp that we should match tags against later on. Using a list
      # instead of a map to ensure order.
      @tag_regexp_list = []
      if @resource.type == GKE_CONSTANTS[:resource_type]
        @tag_regexp_list << [
          GKE_CONSTANTS[:resource_type], @compiled_kubernetes_tag_regexp
        ]
      end

      # Determine the common labels that should be added to all log entries
      # processed by this logging agent.
      @common_labels = determine_agent_level_common_labels(@resource)

      # The resource and labels are now set up; ensure they can't be modified
      # without first duping them.
      @resource.freeze
      @resource.labels.freeze
      @common_labels.freeze

      if @use_grpc
        @construct_log_entry = method(:construct_log_entry_in_grpc_format)
        @write_request = method(:write_request_via_grpc)
      else
        @construct_log_entry = method(:construct_log_entry_in_rest_format)
        @write_request = method(:write_request_via_rest)
      end

      return unless [Common::Platform::GCE, Common::Platform::EC2].include?(@platform)

      # Log an informational message containing the Logs viewer URL
      @log.info 'Logs viewer address: https://console.cloud.google.com/logs/',
                "viewer?project=#{@project_id}&resource=#{@resource.type}/",
                "instance_id/#{@vm_id}"
    end

    def start
      super
      init_api_client
      @successful_call = false
      @timenanos_warning = false

      return unless @statusz_port.positive?

      @log.info "Starting statusz server on port #{@statusz_port}"
      server_create(:out_google_cloud_statusz,
                    @statusz_port,
                    bind: '127.0.0.1') do |data, conn|
        if data.split(' ')[1] == '/statusz'
          write_html_response(data, conn, 200, Statusz.response(self))
        else
          write_html_response(data, conn, 404, "Not found\n")
        end
      end
    end

    def shutdown
      super
      # Export metrics on shutdown. This is a best-effort attempt, and it might
      # fail, for instance if there was a recent write to the same time series.
      @registry&.export
    end

    def write(chunk)
      grouped_entries = group_log_entries_by_tag_and_local_resource_id(chunk)

      requests_to_send = []
      grouped_entries.each do |(tag, local_resource_id), arr|
        entries = []
        group_level_resource, group_level_common_labels =
          determine_group_level_monitored_resource_and_labels(
            tag, local_resource_id
          )

        arr.each do |time, record|
          entry_level_resource, entry_level_common_labels =
            determine_entry_level_monitored_resource_and_labels(
              group_level_resource, group_level_common_labels, record
            )

          is_json = false
          if @detect_json
            # Save the following fields if available, then clear them out to
            # allow for determining whether we should parse the log or message
            # field.
            # This list should be in sync with
            # https://cloud.google.com/logging/docs/agent/configuration#special-fields.
            preserved_keys = [
              'time',
              'timeNanos',
              'timestamp',
              'timestampNanos',
              'timestampSeconds',
              'severity',
              @http_request_key,
              @insert_id_key,
              @labels_key,
              @operation_key,
              @source_location_key,
              @span_id_key,
              @trace_key,
              @trace_sampled_key
            ]

            # If the log is json, we want to export it as a structured log
            # unless there is additional metadata that would be lost.
            record_json = nil
            if (record.keys - preserved_keys).length == 1
              %w[log message msg].each do |field|
                record_json = parse_json_or_nil(record[field]) if record.key?(field)
              end
            end
            unless record_json.nil?
              # Propagate these if necessary. Note that we don't want to
              # override these keys in the JSON we've just parsed.
              preserved_keys.each do |key|
                record_json[key] ||= record[key] if
                  record.key?(key) && !record_json.key?(key)
              end

              record = record_json
              is_json = true
            end
          end

          ts_secs, ts_nanos, timestamp = compute_timestamp(record, time)
          ts_secs, ts_nanos = adjust_timestamp_if_invalid(timestamp, Time.now) \
            if @adjust_invalid_timestamps && timestamp

          severity = compute_severity(
            entry_level_resource.type, record, entry_level_common_labels
          )

          dynamic_labels_from_payload = parse_labels(record)

          if dynamic_labels_from_payload
            entry_level_common_labels.merge!(
              dynamic_labels_from_payload
            )
          end

          entry = @construct_log_entry.call(entry_level_common_labels,
                                            entry_level_resource,
                                            severity,
                                            ts_secs,
                                            ts_nanos)

          insert_id = record.delete(@insert_id_key)
          entry.insert_id = insert_id if insert_id
          span_id = record.delete(@span_id_key)
          entry.span_id = span_id if span_id
          trace = record.delete(@trace_key)
          entry.trace = compute_trace(trace) if trace
          trace_sampled = record.delete(@trace_sampled_key)
          entry.trace_sampled = parse_bool(trace_sampled) unless
            trace_sampled.nil?

          set_log_entry_fields(record, entry)
          set_payload(entry_level_resource.type, record, entry, is_json)

          entries.push(entry)
        end
        # Don't send an empty request if we rejected all the entries.
        next if entries.empty?

        log_name = "projects/#{@project_id}/logs/#{log_name(
          tag, group_level_resource
        )}"

        requests_to_send << {
          entries: entries,
          log_name: log_name,
          resource: group_level_resource,
          labels: group_level_common_labels
        }
      end

      if @split_logs_by_tag
        requests_to_send.each do |request|
          @write_request.call(**request)
        end
      else
        # Combine all requests into one. The request level "log_name" will be
        # ported to the entry level. The request level "resource" and "labels"
        # are ignored as they should have been folded into the entry level
        # "resource" and "labels" already anyway.
        combined_entries = []
        requests_to_send.each do |request|
          request[:entries].each do |entry|
            # Modify entries in-place as they are not needed later on.
            entry.log_name = request[:log_name]
          end
          combined_entries.concat(request[:entries])
        end
        @write_request.call(entries: combined_entries) unless
          combined_entries.empty?
      end
    end

    def multi_workers_ready?
      true
    end

    def self.version_string
      @version_string ||= "google-fluentd/#{PLUGIN_VERSION}"
    end

    def update_uptime
      now = Time.now.to_i
      @uptime_metric.increment(
        by: now - @uptime_update_time,
        labels: { version: Fluent::GoogleCloudOutput.version_string }
      )
      @uptime_update_time = now
    end

    private

    def write_html_response(data, conn, code, response)
      @log.info "#{conn.remote_host} - - " \
                "#{Time.now.strftime('%d/%b/%Y:%H:%M:%S %z')} " \
                "\"#{data.lines.first.strip}\" #{code} #{response.bytesize}"
      conn.write "HTTP/1.1 #{code}\r\n"
      conn.write "Content-Type: text/html\r\n"
      conn.write "Content-Length: #{response.bytesize}\r\n"
      conn.write "\r\n"
      conn.write response
    end

    def compute_trace(trace)
      return trace unless @autoformat_stackdriver_trace &&
                          STACKDRIVER_TRACE_ID_REGEXP.match(trace)

      "projects/#{@project_id}/traces/#{trace}"
    end

    def construct_log_entry_in_grpc_format(labels,
                                           resource,
                                           severity,
                                           ts_secs,
                                           ts_nanos)
      entry = Google::Cloud::Logging::V2::LogEntry.new(
        labels: labels,
        resource: Google::Api::MonitoredResource.new(
          type: resource.type,
          labels: resource.labels.to_h
        ),
        severity: grpc_severity(severity)
      )
      # If "seconds" is null or not an integer, we will omit the timestamp
      # field and defer the decision on how to handle it to the downstream
      # Logging API. If "nanos" is null or not an integer, it will be set
      # to 0.
      if ts_secs.is_a?(Integer)
        ts_nanos = 0 unless ts_nanos.is_a?(Integer)
        entry.timestamp = Google::Protobuf::Timestamp.new(
          seconds: ts_secs,
          nanos: ts_nanos
        )
      end
      entry
    end

    def construct_log_entry_in_rest_format(labels,
                                           resource,
                                           severity,
                                           ts_secs,
                                           ts_nanos)
      # Remove the labels if we didn't populate them with anything.
      resource.labels = nil if resource.labels.empty?
      Google::Apis::LoggingV2::LogEntry.new(
        labels: labels,
        resource: resource,
        severity: severity,
        timestamp: {
          seconds: ts_secs,
          nanos: ts_nanos
        }
      )
    end

    def write_request_via_grpc(entries:,
                               log_name: '',
                               resource: nil,
                               labels: {})
      client = api_client
      entries_count = entries.length
      client.write_log_entries(
        entries: entries,
        log_name: log_name,
        # Leave resource nil if it's nil.
        resource: if resource
                    Google::Api::MonitoredResource.new(
                      type: resource.type,
                      labels: resource.labels.to_h
                    )
                  end,
        labels: labels.map do |k, v|
          [k.encode('utf-8'), convert_to_utf8(v)]
        end.to_h,
        partial_success: true
      )
      increment_successful_requests_count
      increment_ingested_entries_count(entries_count)

      # Let the user explicitly know when the first call succeeded, to
      # aid with verification and troubleshooting.
      unless @successful_call
        @successful_call = true
        @log.info 'Successfully sent gRPC to Stackdriver Logging API.'
      end
    rescue Google::Cloud::Error => e
      # GRPC::BadStatus is wrapped in error.cause.
      error = e.cause

      # See the mapping between HTTP status and gRPC status code at:
      # https://github.com/grpc/grpc/blob/master/src/core/lib/transport/status_conversion.cc
      case error
      # Server error, so retry via re-raising the error.
      when \
          # HTTP status 500 (Internal Server Error).
          GRPC::Internal,
          # HTTP status 501 (Not Implemented).
          GRPC::Unimplemented,
          # HTTP status 503 (Service Unavailable).
          GRPC::Unavailable,
          # HTTP status 504 (Gateway Timeout).
          GRPC::DeadlineExceeded
        increment_retried_entries_count(entries_count, error.code)
        @log.debug "Retrying #{entries_count} log message(s) later.",
                   error: error.to_s, error_code: error.code.to_s
        raise error

      # Most client errors indicate a problem with the request itself and
      # should not be retried.
      when \
          # HTTP status 401 (Unauthorized).
          # These are usually solved via a `gcloud auth` call, or by modifying
          # the permissions on the Google Cloud project.
          GRPC::Unauthenticated,
          # HTTP status 404 (Not Found).
          GRPC::NotFound,
          # HTTP status 409 (Conflict).
          GRPC::Aborted,
          # HTTP status 412 (Precondition Failed).
          GRPC::FailedPrecondition,
          # HTTP status 429 (Too Many Requests).
          GRPC::ResourceExhausted,
          # HTTP status 499 (Client Closed Request).
          GRPC::Cancelled,
          # the remaining http codes in both 4xx and 5xx category.
          # It's debatable whether to retry or drop these log entries.
          # This decision is made to avoid retrying forever due to
          # client errors.
          GRPC::Unknown
        increment_failed_requests_count(error.code)
        increment_dropped_entries_count(entries_count, error.code)
        @log.warn "Dropping #{entries_count} log message(s)",
                  error: error.to_s, error_code: error.code.to_s

      # As partial_success is enabled, valid entries should have been
      # written even if some other entries fail due to InvalidArgument or
      # PermissionDenied errors. Only invalid entries will be dropped.
      when \
          # HTTP status 400 (Bad Request).
          GRPC::InvalidArgument,
          # HTTP status 403 (Forbidden).
          GRPC::PermissionDenied
        error_details_map = construct_error_details_map_grpc(e)
        if error_details_map.empty?
          increment_failed_requests_count(error.code)
          increment_dropped_entries_count(entries_count, error.code)
          @log.warn "Dropping #{entries_count} log message(s)",
                    error: error.to_s, error_code: error.code.to_s
        else
          error_details_map.each do |(error_code, error_message), indexes|
            partial_errors_count = indexes.length
            increment_dropped_entries_count(partial_errors_count,
                                            error_code)
            entries_count -= partial_errors_count
            @log.warn "Dropping #{partial_errors_count} log message(s)",
                      error: error_message, error_code: error_code.to_s
          end
          # Consider partially successful requests successful.
          increment_successful_requests_count
          increment_ingested_entries_count(entries_count)
        end

      else
        # Assume it's a problem with the request itself and don't retry.
        error_code = if error.respond_to?(:code)
                       error.code
                     else
                       GRPC::Core::StatusCodes::UNKNOWN
                     end
        increment_failed_requests_count(error_code)
        increment_dropped_entries_count(entries_count, error_code)
        @log.error "Unknown response code #{error_code} from the server," \
                   " dropping #{entries_count} log message(s)",
                   error: error.to_s, error_code: error_code.to_s
      end

    # Got an unexpected error (not Google::Cloud::Error) from the
    # google-cloud-logging lib.
    rescue StandardError => e
      increment_failed_requests_count(GRPC::Core::StatusCodes::UNKNOWN)
      increment_dropped_entries_count(entries_count,
                                      GRPC::Core::StatusCodes::UNKNOWN)
      @log.error "Unexpected error type #{e.class.name} from the client" \
                 " library, dropping #{entries_count} log message(s)",
                 error: e.to_s
    end

    def write_request_via_rest(entries:,
                               log_name: '',
                               resource: nil,
                               labels: {})
      client = api_client
      entries_count = entries.length
      client.write_entry_log_entries(
        Google::Apis::LoggingV2::WriteLogEntriesRequest.new(
          entries: entries,
          log_name: log_name,
          resource: resource,
          labels: labels,
          partial_success: true
        ),
        options: { api_format_version: '2' }
      )
      increment_successful_requests_count
      increment_ingested_entries_count(entries_count)

      # Let the user explicitly know when the first call succeeded, to aid
      # with verification and troubleshooting.
      unless @successful_call
        @successful_call = true
        @log.info 'Successfully sent to Stackdriver Logging API.'
      end
    rescue Google::Apis::ServerError => e
      # 5xx server errors. Retry via re-raising the error.
      increment_retried_entries_count(entries_count, e.status_code)
      @log.debug "Retrying #{entries_count} log message(s) later.",
                 error: e.to_s, error_code: e.status_code.to_s
      raise e
    rescue Google::Apis::AuthorizationError => e
      # 401 authorization error.
      # These are usually solved via a `gcloud auth` call, or by modifying
      # the permissions on the Google Cloud project.
      increment_failed_requests_count(e.status_code)
      increment_dropped_entries_count(entries_count, e.status_code)
      @log.warn "Dropping #{entries_count} log message(s)",
                error: e.to_s, error_code: e.status_code.to_s
    rescue Google::Apis::ClientError => e
      # 4xx client errors. Most client errors indicate a problem with the
      # request itself and should not be retried.
      error_details_map = construct_error_details_map(e)
      if error_details_map.empty?
        increment_failed_requests_count(e.status_code)
        increment_dropped_entries_count(entries_count, e.status_code)
        @log.warn "Dropping #{entries_count} log message(s)",
                  error: e.to_s, error_code: e.status_code.to_s
      else
        error_details_map.each do |(error_code, error_message), indexes|
          partial_errors_count = indexes.length
          increment_dropped_entries_count(partial_errors_count, error_code)
          entries_count -= partial_errors_count
          @log.warn "Dropping #{partial_errors_count} log message(s)",
                    error: error_message,
                    error_code: "google.rpc.Code[#{error_code}]"
        end
        # Consider partially successful requests successful.
        increment_successful_requests_count
        increment_ingested_entries_count(entries_count)
      end
    end

    def parse_json_or_nil(input)
      return nil unless input.is_a?(String)

      input.each_codepoint do |c|
        if c == 123
          # left curly bracket (U+007B)
          begin
            return JSON.parse(input)
          rescue JSON::ParserError
            return nil
          end
        else
          # Break (and return nil) unless the current character is whitespace,
          # in which case we continue to look for a left curly bracket.
          # Whitespace as per the JSON spec are: tabulation (U+0009),
          # line feed (U+000A), carriage return (U+000D), and space (U+0020).
          break unless [9, 10, 13, 32].include?(c)
        end
      end
      nil
    end

    # Set regexp patterns to parse tags and logs.
    def set_regexp_patterns
      @compiled_kubernetes_tag_regexp = Regexp.new(@kubernetes_tag_regexp) if
        @kubernetes_tag_regexp

      @compiled_http_latency_regexp =
        /^\s*(?<seconds>\d+)(?<decimal>\.\d+)?\s*s\s*$/
    end

    # Determine the common labels that should be added to all log entries
    # processed by this logging agent.
    def determine_agent_level_common_labels(resource)
      labels = {}
      # User can specify labels via config. We want to capture those as well.
      labels.merge!(@labels) if @labels

      case resource.type
      # GAE, Cloud Dataflow, Cloud Dataproc and Cloud ML.
      when APPENGINE_CONSTANTS[:resource_type],
           DATAFLOW_CONSTANTS[:resource_type],
           DATAPROC_CONSTANTS[:resource_type],
           ML_CONSTANTS[:resource_type]
        labels.merge!(
          "#{COMPUTE_CONSTANTS[:service]}/resource_id" => @vm_id,
          "#{COMPUTE_CONSTANTS[:service]}/resource_name" => @vm_name,
          "#{COMPUTE_CONSTANTS[:service]}/zone" => @zone
        )

      # GCE instance and GKE container.
      when COMPUTE_CONSTANTS[:resource_type],
           GKE_CONSTANTS[:resource_type]
        labels["#{COMPUTE_CONSTANTS[:service]}/resource_name"] = @vm_name

      # EC2.
      when EC2_CONSTANTS[:resource_type]
        labels["#{EC2_CONSTANTS[:service]}/resource_name"] = @vm_name
      end
      labels
    end

    # Group the log entries by tag and local_resource_id pairs. Also filter out
    # invalid non-Hash entries.
    def group_log_entries_by_tag_and_local_resource_id(chunk)
      groups = {}
      chunk.msgpack_each do |tag, time, record|
        unless record.is_a?(Hash)
          @log.warn 'Dropping log entries with malformed record: ' \
                    "'#{record.inspect}' from tag '#{tag}' at '#{time}'. " \
                    'A log record should be in JSON format.'
          next
        end
        sanitized_tag = sanitize_tag(tag)
        if sanitized_tag.nil?
          @log.warn "Dropping log entries with invalid tag: '#{tag.inspect}'." \
                    ' A tag should be a string with utf8 characters.'
          next
        end
        local_resource_id = record.delete(LOCAL_RESOURCE_ID_KEY)
        # A nil local_resource_id means "fall back to legacy".
        hash_key = [sanitized_tag, local_resource_id].freeze
        groups[hash_key] ||= []
        groups[hash_key].push([time, record])
      end
      groups
    end

    # Determine the group level monitored resource and common labels shared by a
    # collection of entries.
    def determine_group_level_monitored_resource_and_labels(tag,
                                                            local_resource_id)
      resource = @resource.dup
      resource.labels = @resource.labels.dup
      common_labels = @common_labels.dup

      # Change the resource type and set matched_regexp_group if the tag matches
      # certain regexp.
      matched_regexp_group = nil # @tag_regexp_list can be an empty list.
      @tag_regexp_list.each do |derived_type, tag_regexp|
        matched_regexp_group = tag_regexp.match(tag)
        if matched_regexp_group
          resource.type = derived_type
          break
        end
      end

      # Determine the monitored resource based on the local_resource_id.
      # Different monitored resource types have unique ids in different format.
      # We will query Metadata Agent for the monitored resource. Return the
      # legacy monitored resource (either the instance resource or the resource
      # inferred from the tag) if failed to get a monitored resource from
      # Metadata Agent with this key.
      #
      # Examples:
      # // GKE Pod.
      # "k8s_pod.<namespace_name>.<pod_name>"
      # // GKE container.
      # "k8s_container.<namespace_name>.<pod_name>.<container_name>"
      if local_resource_id
        converted_resource = monitored_resource_from_local_resource_id(
          local_resource_id
        )
        resource = converted_resource if converted_resource
      end

      # Once the resource type is settled down, determine the labels.
      case resource.type
      # GKE container.
      when GKE_CONSTANTS[:resource_type]
        if matched_regexp_group
          # We only expect one occurrence of each key in the match group.
          resource_labels_candidates =
            matched_regexp_group.names.zip(matched_regexp_group.captures).to_h
          common_labels_candidates = resource_labels_candidates.dup
          resource.labels.merge!(
            delete_and_extract_labels(
              resource_labels_candidates,
              # The kubernetes_tag_regexp is poorly named. 'namespace_name' is
              # in fact 'namespace_id'. 'pod_name' is in fact 'pod_id'.
              # TODO(qingling128): Figure out how to put this map into
              # constants like GKE_CONSTANTS[:extra_resource_labels].
              'container_name' => 'container_name',
              'namespace_name' => 'namespace_id',
              'pod_name' => 'pod_id'
            )
          )

          common_labels.merge!(
            delete_and_extract_labels(
              common_labels_candidates,
              GKE_CONSTANTS[:extra_common_labels]
                .map { |l| [l, "#{GKE_CONSTANTS[:service]}/#{l}"] }.to_h
            )
          )
        end

      # TODO(qingling128): Temporary fallback for metadata agent restarts.
      # K8s resources.
      when K8S_CONTAINER_CONSTANTS[:resource_type],
           K8S_POD_CONSTANTS[:resource_type],
           K8S_NODE_CONSTANTS[:resource_type]
        common_labels.delete("#{COMPUTE_CONSTANTS[:service]}/resource_name")

      end

      # Cloud Dataflow and Cloud ML.
      # These labels can be set via the 'labels' option.
      # Report them as monitored resource labels instead of common labels.
      # e.g. "dataflow.googleapis.com/job_id" => "job_id"
      [DATAFLOW_CONSTANTS, ML_CONSTANTS].each do |service_constants|
        next unless resource.type == service_constants[:resource_type]

        resource.labels.merge!(
          delete_and_extract_labels(
            common_labels, service_constants[:extra_resource_labels]
              .map { |l| ["#{service_constants[:service]}/#{l}", l] }.to_h
          )
        )
      end

      resource.freeze
      resource.labels.freeze
      common_labels.freeze

      [resource, common_labels]
    end

    # Extract entry level monitored resource and common labels that should be
    # applied to individual entries.
    def determine_entry_level_monitored_resource_and_labels(
      group_level_resource, group_level_common_labels, record
    )
      resource = group_level_resource.dup
      resource.labels = group_level_resource.labels.dup
      common_labels = group_level_common_labels.dup

      case resource.type
      # GKE container.
      when GKE_CONSTANTS[:resource_type]
        # Move the stdout/stderr annotation from the record into a label.
        common_labels.merge!(
          delete_and_extract_labels(
            record, 'stream' => "#{GKE_CONSTANTS[:service]}/stream"
          )
        )

        # If the record has been annotated by the kubernetes_metadata_filter
        # plugin, then use that metadata. Otherwise, rely on commonLabels
        # populated from the group's tag.
        if record.key?('kubernetes')
          resource.labels.merge!(
            delete_and_extract_labels(
              record['kubernetes'], GKE_CONSTANTS[:extra_resource_labels]
                .map { |l| [l, l] }.to_h
            )
          )
          common_labels.merge!(
            delete_and_extract_labels(
              record['kubernetes'], GKE_CONSTANTS[:extra_common_labels]
                .map { |l| [l, "#{GKE_CONSTANTS[:service]}/#{l}"] }.to_h
            )
          )
          # Prepend label/ to all user-defined labels' keys.
          if record['kubernetes'].key?('labels')
            common_labels.merge!(
              delete_and_extract_labels(
                record['kubernetes']['labels'], record['kubernetes']['labels']
                  .map { |key, _| [key, "label/#{key}"] }.to_h
              )
            )
          end
          # We've explicitly consumed all the fields we care about -- don't
          # litter the log entries with the remaining fields that the kubernetes
          # metadata filter plugin includes (or an empty 'kubernetes' field).
          record.delete('kubernetes')
          record.delete('docker')
        end
      end

      # If the name of a field in the record is present in the @label_map
      # configured by users, report its value as a label and do not send that
      # field as part of the payload.
      common_labels.merge!(delete_and_extract_labels(record, @label_map))

      # Cloud Dataflow and Cloud ML.
      # These labels can be set via the 'labels' or 'label_map' options.
      # Report them as monitored resource labels instead of common labels.
      # e.g. "dataflow.googleapis.com/job_id" => "job_id"
      [DATAFLOW_CONSTANTS, ML_CONSTANTS].each do |service_constants|
        next unless resource.type == service_constants[:resource_type]

        resource.labels.merge!(
          delete_and_extract_labels(
            common_labels, service_constants[:extra_resource_labels]
              .map { |l| ["#{service_constants[:service]}/#{l}", l] }.to_h
          )
        )
      end

      [resource, common_labels]
    end

    def time_or_nil(ts_secs, ts_nanos)
      Time.at((Integer ts_secs), (Integer ts_nanos) / 1_000.0)
    rescue ArgumentError, TypeError
      nil
    end

    def compute_timestamp(record, time)
      if record.key?('timestamp') &&
         record['timestamp'].is_a?(Hash) &&
         record['timestamp'].key?('seconds') &&
         record['timestamp'].key?('nanos')
        ts_secs = record['timestamp']['seconds']
        ts_nanos = record['timestamp']['nanos']
        record.delete('timestamp')
        timestamp = time_or_nil(ts_secs, ts_nanos)
      elsif record.key?('timestampSeconds') &&
            record.key?('timestampNanos')
        ts_secs = record.delete('timestampSeconds')
        ts_nanos = record.delete('timestampNanos')
        timestamp = time_or_nil(ts_secs, ts_nanos)
      elsif record.key?('timeNanos')
        # This is deprecated since the precision is insufficient.
        # Use timestampSeconds/timestampNanos instead
        nanos = record.delete('timeNanos')
        ts_secs = (nanos / 1_000_000_000).to_i
        ts_nanos = nanos % 1_000_000_000
        unless @timenanos_warning
          # Warn the user this is deprecated, but only once to avoid spam.
          @timenanos_warning = true
          @log.warn 'timeNanos is deprecated - please use ' \
            'timestampSeconds and timestampNanos instead.'
        end
        timestamp = time_or_nil(ts_secs, ts_nanos)
      elsif record.key?('time')
        # k8s ISO8601 timestamp
        begin
          timestamp = Time.iso8601(record.delete('time'))
        rescue StandardError
          timestamp = Time.at(time)
        end
        ts_secs = timestamp.tv_sec
        ts_nanos = timestamp.tv_nsec
      else
        timestamp = Time.at(time)
        ts_secs = timestamp.tv_sec
        ts_nanos = timestamp.tv_nsec
      end
      ts_secs = begin
        Integer ts_secs
      rescue ArgumentError, TypeError
        ts_secs
      end
      ts_nanos = begin
        Integer ts_nanos
      rescue ArgumentError, TypeError
        ts_nanos
      end

      [ts_secs, ts_nanos, timestamp]
    end

    # Adjust timestamps from the future.
    # The base case is:
    # 0. The parsed timestamp is less than one day into the future.
    # This is allowed by the API, and should be left unchanged.
    #
    # Beyond that, there are two cases:
    # 1. The parsed timestamp is later in the current year:
    # This can happen when system log lines from previous years are missing
    # the year, so the date parser assumes the current year.
    # We treat these lines as coming from last year. This could label
    # 2-year-old logs incorrectly, but this probably isn't super important.
    #
    # 2. The parsed timestamp is past the end of the current year:
    # Since the year is different from the current year, this isn't the
    # missing year in system logs. It is unlikely that users explicitly
    # write logs at a future date. This could result from an unsynchronized
    # clock on a VM, or some random value being parsed as the timestamp.
    # We reset the timestamp on those lines to the default value and let the
    # downstream API handle it.
    def adjust_timestamp_if_invalid(timestamp, current_time)
      ts_secs = timestamp.tv_sec
      ts_nanos = timestamp.tv_nsec

      next_year = Time.mktime(current_time.year + 1)
      one_day_later = current_time.to_datetime.next_day.to_time
      if timestamp < one_day_later # Case 0.
        # Leave the timestamp as-is.
      elsif timestamp >= next_year # Case 2.
        ts_secs = 0
        ts_nanos = 0
      else # Case 1.
        adjusted_timestamp = timestamp.to_datetime.prev_year.to_time
        ts_secs = adjusted_timestamp.tv_sec
        # The value of ts_nanos should not change when subtracting a year.
      end

      [ts_secs, ts_nanos]
    end

    def compute_severity(resource_type, record, entry_level_common_labels)
      if record.key?('severity')
        return parse_severity(record.delete('severity'))
      elsif resource_type == GKE_CONSTANTS[:resource_type]
        stream = entry_level_common_labels["#{GKE_CONSTANTS[:service]}/stream"]
        return GKE_CONSTANTS[:stream_severity_map].fetch(stream, 'DEFAULT')
      end

      'DEFAULT'
    end

    def set_log_entry_fields(record, entry)
      # TODO(qingling128) On the next major after 0.7.4, make all logEntry
      # subfields behave the same way: if the field is not in the correct
      # format, log an error in the Fluentd log and remove this field from
      # payload. This is the preferred behavior per PM decision.
      LOG_ENTRY_FIELDS_MAP.each do |field_name, config|
        payload_key, subfields, grpc_class, non_grpc_class = config
        begin
          payload_key = instance_variable_get(payload_key)
          fields = record[payload_key]
          record.delete(payload_key) if fields.nil?
          next unless fields.is_a?(Hash)

          extracted_subfields = subfields.each_with_object({}) \
            do |(original_key, destination_key, cast_fn), extracted_fields|
              value = fields.delete(original_key)
              next if value.nil?

              begin
                casted_value = send(cast_fn, value)
              rescue TypeError
                @log.error "Failed to #{cast_fn} for #{field_name}." \
                           "#{original_key} with value #{value.inspect}.", err
                next
              end
              next if casted_value.nil?

              extracted_fields[destination_key] = casted_value
            end

          next unless extracted_subfields

          output = if @use_grpc
                     Object.const_get(grpc_class).new
                   else
                     Object.const_get(non_grpc_class).new
                   end
          extracted_subfields.each do |key, value|
            output.send("#{key}=", value)
          end

          record.delete(payload_key) if fields.empty?

          entry.send("#{field_name}=", output)
        rescue StandardError => e
          @log.error "Failed to set log entry field for #{field_name}.", e
        end
      end
    end

    # Parse labels. Return nil if not set.
    def parse_labels(record)
      payload_labels = record.delete(@labels_key)
      return nil unless payload_labels

      unless payload_labels.is_a?(Hash)
        @log.error "Invalid value of '#{@labels_key}' in the payload: " \
                   "#{payload_labels}. Labels need to be a JSON object."
        return nil
      end

      non_string_keys = payload_labels.each_with_object([]) do |(k, v), a|
        a << k unless k.is_a?(String) && v.is_a?(String)
      end
      unless non_string_keys.empty?
        @log.error "Invalid value of '#{@labels_key}' in the payload: " \
                   "#{payload_labels}. Labels need string values for all " \
                   "keys; keys #{non_string_keys} don't."
        return nil
      end
      payload_labels
    rescue StandardError => e
      @log.error "Failed to extract '#{@labels_key}' from payload.", e
      nil
    end

    # Values permitted by the API for 'severity' (which is an enum).
    VALID_SEVERITIES = Set.new(
      %w[DEFAULT DEBUG INFO NOTICE WARNING ERROR CRITICAL ALERT EMERGENCY]
    ).freeze

    # Translates other severity strings to one of the valid values above.
    SEVERITY_TRANSLATIONS = {
      # log4j levels (both current and obsolete).
      'WARN' => 'WARNING',
      'FATAL' => 'CRITICAL',
      'TRACE' => 'DEBUG',
      'TRACE_INT' => 'DEBUG',
      'FINE' => 'DEBUG',
      'FINER' => 'DEBUG',
      'FINEST' => 'DEBUG',
      # java.util.logging levels (only missing ones from above listed).
      'SEVERE' => 'ERROR',
      'CONFIG' => 'DEBUG',
      # nginx levels (only missing ones from above listed).
      'CRIT' => 'CRITICAL',
      'EMERG' => 'EMERGENCY',
      # single-letter levels.  Note E->ERROR and D->DEBUG.
      'D' => 'DEBUG',
      'I' => 'INFO',
      'N' => 'NOTICE',
      'W' => 'WARNING',
      'E' => 'ERROR',
      'C' => 'CRITICAL',
      'A' => 'ALERT',
      # other misc. translations.
      'INFORMATION' => 'INFO',
      'ERR' => 'ERROR',
      'F' => 'CRITICAL'
    }.freeze

    def parse_severity(severity_str)
      # The API is case insensitive, but uppercase to make things simpler.
      severity = severity_str.to_s.upcase.strip

      # If the severity is already valid, just return it.
      return severity if VALID_SEVERITIES.include?(severity)

      # If the severity is an integer (string) return it as an integer,
      # truncated to the closest valid value (multiples of 100 between 0-800).
      if /\A\d+\z/ =~ severity
        begin
          numeric_severity = (severity.to_i / 100) * 100
          case
          when numeric_severity.negative?
            return 0
          when numeric_severity > 800
            return 800
          else
            return numeric_severity
          end
        rescue StandardError
          return 'DEFAULT'
        end
      end

      # Try to translate the severity.
      return SEVERITY_TRANSLATIONS[severity] if SEVERITY_TRANSLATIONS.key?(severity)

      # If all else fails, use 'DEFAULT'.
      'DEFAULT'
    end

    GRPC_SEVERITY_MAPPING = {
      'DEFAULT' => Google::Cloud::Logging::Type::LogSeverity::DEFAULT,
      'DEBUG' => Google::Cloud::Logging::Type::LogSeverity::DEBUG,
      'INFO' => Google::Cloud::Logging::Type::LogSeverity::INFO,
      'NOTICE' => Google::Cloud::Logging::Type::LogSeverity::NOTICE,
      'WARNING' => Google::Cloud::Logging::Type::LogSeverity::WARNING,
      'ERROR' => Google::Cloud::Logging::Type::LogSeverity::ERROR,
      'CRITICAL' => Google::Cloud::Logging::Type::LogSeverity::CRITICAL,
      'ALERT' => Google::Cloud::Logging::Type::LogSeverity::ALERT,
      'EMERGENCY' => Google::Cloud::Logging::Type::LogSeverity::EMERGENCY,
      0 => Google::Cloud::Logging::Type::LogSeverity::DEFAULT,
      100 => Google::Cloud::Logging::Type::LogSeverity::DEBUG,
      200 => Google::Cloud::Logging::Type::LogSeverity::INFO,
      300 => Google::Cloud::Logging::Type::LogSeverity::NOTICE,
      400 => Google::Cloud::Logging::Type::LogSeverity::WARNING,
      500 => Google::Cloud::Logging::Type::LogSeverity::ERROR,
      600 => Google::Cloud::Logging::Type::LogSeverity::CRITICAL,
      700 => Google::Cloud::Logging::Type::LogSeverity::ALERT,
      800 => Google::Cloud::Logging::Type::LogSeverity::EMERGENCY
    }.freeze

    def grpc_severity(severity)
      # TODO: find out why this doesn't work.
      # if severity.is_a? String
      #   return Google::Cloud::Logging::Type::LogSeverity.resolve(severity)
      # end
      return GRPC_SEVERITY_MAPPING[severity] if GRPC_SEVERITY_MAPPING.key?(severity)

      severity
    end

    def parse_string(value)
      value.to_s
    end

    def parse_int(value)
      value.to_i
    end

    def parse_bool(value)
      [true, 'true', 1].include?(value)
    end

    def parse_latency(latency)
      # Parse latency.
      # If no valid format is detected, return nil so we can later skip
      # setting latency.
      # Format: whitespace (opt.) + integer + point & decimal (opt.)
      #       + whitespace (opt.) + "s" + whitespace (opt.)
      # e.g.: "1.42 s"
      match = @compiled_http_latency_regexp.match(latency)
      return nil unless match

      # Split the integer and decimal parts in order to calculate
      # seconds and nanos.
      seconds = match['seconds'].to_i
      nanos = (match['decimal'].to_f * 1000 * 1000 * 1000).round
      if @use_grpc
        Google::Protobuf::Duration.new(
          seconds: seconds,
          nanos: nanos
        )
      else
        {
          seconds: seconds,
          nanos: nanos
        }.delete_if { |_, v| v.zero? }
      end
    end

    def format(tag, time, record)
      Fluent::MessagePackFactory
        .engine_factory
        .packer
        .write([tag, time, record])
        .to_s
    end

    # Given a tag, returns the corresponding valid tag if possible, or nil if
    # the tag should be rejected. If 'require_valid_tags' is false, non-string
    # tags are converted to strings, and invalid characters are sanitized;
    # otherwise such tags are rejected.
    def sanitize_tag(tag)
      if @require_valid_tags &&
         (!tag.is_a?(String) || tag == '' || convert_to_utf8(tag) != tag)
        return nil
      end

      tag = convert_to_utf8(tag.to_s)
      tag = '_' if tag == ''
      tag
    end

    # For every original_label => new_label pair in the label_map, delete the
    # original_label from the hash map if it exists, and extract the value to
    # form a map with the new_label as the key.
    def delete_and_extract_labels(hash, label_map)
      return {} if label_map.nil? || !label_map.is_a?(Hash) ||
                   hash.nil? || !hash.is_a?(Hash)

      label_map.each_with_object({}) \
        do |(original_label, new_label), extracted_labels|
          value = hash.delete(original_label)
          extracted_labels[new_label] = convert_to_utf8(value.to_s) if value
        end
    end

    def value_from_ruby(value)
      ret = Google::Protobuf::Value.new
      case value
      when NilClass
        ret.null_value = 0
      when Numeric
        ret.number_value = value
      when String
        ret.string_value = convert_to_utf8(value)
      when TrueClass
        ret.bool_value = true
      when FalseClass
        ret.bool_value = false
      when Google::Protobuf::Struct
        ret.struct_value = value
      when Hash
        ret.struct_value = struct_from_ruby(value)
      when Google::Protobuf::ListValue
        ret.list_value = value
      when Array
        ret.list_value = list_from_ruby(value)
      else
        @log.error "Unknown type: #{value.class}"
        raise Google::Protobuf::Error, "Unknown type: #{value.class}"
      end
      ret
    end

    def list_from_ruby(arr)
      ret = Google::Protobuf::ListValue.new
      arr.each do |v|
        ret.values << value_from_ruby(v)
      end
      ret
    end

    def struct_from_ruby(hash)
      ret = Google::Protobuf::Struct.new
      hash.each do |k, v|
        ret.fields[convert_to_utf8(k.to_s)] ||= value_from_ruby(v)
      end
      ret
    end

    # TODO(qingling128): Fix the inconsistent behavior of 'message', 'log' and
    # 'msg' in the next major version 1.0.0.
    def set_payload(resource_type, record, entry, is_json)
      # Only one of {text_payload, json_payload} will be set.
      text_payload = nil
      json_payload = nil
      # Use JSON if we found valid JSON, or text payload in the following
      # cases:
      # 1. This is an unstructured Container log and the 'log' key is available
      # 2. The only remaining key is 'message'
      if is_json
        json_payload = record
      elsif GKE_CONSTANTS[:resource_type] == resource_type && record.key?('log')
        text_payload = record['log']
      elsif record.size == 1 && record.key?('message')
        text_payload = record['message']
      else
        json_payload = record
      end

      if json_payload
        entry.json_payload = if @use_grpc
                               struct_from_ruby(json_payload)
                             else
                               json_payload
                             end
      elsif text_payload
        text_payload = text_payload.to_s
        entry.text_payload = if @use_grpc
                               convert_to_utf8(text_payload)
                             else
                               text_payload
                             end
      end
    end

    def log_name(tag, resource)
      if resource.type == APPENGINE_CONSTANTS[:resource_type]
        # Add a prefix to Managed VM logs to prevent namespace collisions.
        tag = "#{APPENGINE_CONSTANTS[:service]}/#{tag}"
      elsif resource.type == GKE_CONSTANTS[:resource_type]
        # For Kubernetes logs, use just the container name as the log name
        # if we have it.
        if resource.labels&.key?('container_name')
          sanitized_tag = sanitize_tag(resource.labels['container_name'])
          tag = sanitized_tag unless sanitized_tag.nil?
        end
      end
      ERB::Util.url_encode(tag)
    end

    def init_api_client
      # Set up the logger for the auto-generated Google Cloud APIs.
      Google::Apis.logger = @log
      if @use_grpc
        uri = URI.parse(@logging_api_url)
        host = uri.host
        unless host
          raise Fluent::ConfigError,
                'The logging_api_url option specifies an invalid URL:' \
                " #{@logging_api_url}."
        end
        if @grpc_compression_algorithm
          compression_options =
            GRPC::Core::CompressionOptions.new(
              default_algorithm: @grpc_compression_algorithm
            )
          compression_channel_args = compression_options.to_channel_arg_hash
        else
          compression_channel_args = {}
        end
        if uri.scheme == 'https'
          ssl_creds = GRPC::Core::ChannelCredentials.new
          authentication = Google::Auth.get_application_default
          creds = GRPC::Core::CallCredentials.new(authentication.updater_proc)
          creds = ssl_creds.compose(creds)
        else
          creds = :this_channel_is_insecure
        end
        port = ":#{uri.port}" if uri.port
        user_agent = \
          "#{PLUGIN_NAME}/#{PLUGIN_VERSION} grpc-ruby/#{GRPC::VERSION} " \
          "#{Google::Apis::OS_VERSION}"
        channel_args = { 'grpc.primary_user_agent' => user_agent }
                       .merge!(compression_channel_args)
        @client = Google::Cloud::Logging::V2::LoggingService::Client.new do |config|
          config.credentials = GRPC::Core::Channel.new(
            "#{host}#{port}", channel_args, creds
          )
        end
      else
        # TODO: Use a non-default ClientOptions object.
        Google::Apis::ClientOptions.default.application_name = PLUGIN_NAME
        Google::Apis::ClientOptions.default.application_version = PLUGIN_VERSION
        @client = Google::Apis::LoggingV2::LoggingService.new
        @client.authorization = Google::Auth.get_application_default(
          Common::LOGGING_SCOPE
        )
      end
    end

    def api_client
      # For gRPC side, the Channel will take care of tokens and their renewal
      # (https://grpc.io/docs/guides/auth.html#authentication-api).
      if !@use_grpc && @client.authorization.expired?
        begin
          @client.authorization.fetch_access_token!
        rescue MultiJson::ParseError
          # Workaround an issue in the API client; just re-raise a more
          # descriptive error for the user (which will still cause a retry).
          raise Google::APIClient::ClientError,
                'Unable to fetch access token (no scopes configured?)'
        end
      end
      @client
    end

    # Encode as UTF-8. If 'coerce_to_utf8' is set to true in the config, any
    # non-UTF-8 character would be replaced by the string specified by
    # 'non_utf8_replacement_string'. If 'coerce_to_utf8' is set to false, any
    # non-UTF-8 character would trigger the plugin to error out.
    def convert_to_utf8(input)
      if @coerce_to_utf8
        input.encode(
          'utf-8',
          invalid: :replace,
          undef: :replace,
          replace: @non_utf8_replacement_string
        )
      else
        begin
          input.encode('utf-8')
        rescue EncodingError
          @log.error 'Encountered encoding issues potentially due to non ' \
                     'UTF-8 characters. To allow non-UTF-8 characters and ' \
                     'replace them with spaces, please set "coerce_to_utf8" ' \
                     'to true.'
          raise
        end
      end
    end

    # Extract a map of error details from a potentially partially successful
    # REST request.
    #
    # The keys in this map are [error_code, error_message] pairs, and the values
    # are a list of stringified indexes of log entries that failed due to this
    # error.
    #
    # A sample error.body looks like:
    # {
    #   "error": {
    #     "code": 403,
    #     "message": "User not authorized.",
    #     "status": "PERMISSION_DENIED",
    #     "details": [
    #       {
    #         "@type": "type.googleapis.com/google.logging.v2.WriteLogEntriesPar
    #           tialErrors",
    #         "logEntryErrors": {
    #           "0": {
    #             "code": 7,
    #             "message": "User not authorized."
    #           },
    #           "1": {
    #             "code": 3,
    #             "message": "Log name contains illegal character :"
    #           },
    #           "3": {
    #             "code": 3,
    #             "message": "Log name contains illegal character :"
    #           }
    #         }
    #       },
    #       {
    #         "@type": "type.googleapis.com/google.rpc.DebugInfo",
    #         "detail": ...
    #       }
    #     ]
    #   }
    # }
    #
    # The root level "code", "message", and "status" simply match the root
    # cause of the first failed log entry. For example, if we switched the order
    # of the log entries, then we would get:
    # {
    #    "error" : {
    #       "code" : 400,
    #       "message" : "Log name contains illegal character :",
    #       "status" : "INVALID_ARGUMENT",
    #       "details": ...
    #    }
    # }
    # We will ignore it anyway and look at the details instead which includes
    # info for all failed log entries.
    #
    # In this example, the logEntryErrors that we care are:
    # {
    #   "0": {
    #     "code": 7,
    #     "message": "User not authorized."
    #   },
    #   "1": {
    #     "code": 3,
    #     "message": "Log name contains illegal character :"
    #   },
    #   "3": {
    #     "code": 3,
    #     "message": "Log name contains illegal character :"
    #   }
    # }
    #
    # The ultimate map that is constructed is:
    # {
    #   [7, 'User not authorized.']: ['0'],
    #   [3, 'Log name contains illegal character :']: ['1', '3']
    # }
    def construct_error_details_map(error)
      error_details_map = Hash.new { |h, k| h[k] = [] }

      error_details = ensure_array(
        ensure_hash(ensure_hash(JSON.parse(error.body))['error'])['details']
      )
      partial_errors = error_details.detect(
        -> { raise JSON::ParserError, "No type #{PARTIAL_ERROR_FIELD}." }
      ) do |error_detail|
        ensure_hash(error_detail)['@type'] == PARTIAL_ERROR_FIELD
      end
      log_entry_errors = ensure_hash(
        ensure_hash(partial_errors)['logEntryErrors']
      )
      log_entry_errors.each do |index, log_entry_error|
        error_hash = ensure_hash(log_entry_error)
        unless error_hash['code'] && error_hash['message']
          raise JSON::ParserError,
                "Entry #{index} is missing 'code' or 'message'."
        end
        error_key = [error_hash['code'], error_hash['message']].freeze
        # TODO(qingling128): Convert indexes to integers.
        error_details_map[error_key] << index
      end
      error_details_map
    rescue JSON::ParserError => e
      @log.warn 'Failed to extract log entry errors from the error details:' \
                " #{error.body}.", error: e
      {}
    end

    # Extract a map of error details from a potentially partially successful
    # gRPC request.
    #
    # The keys in this map are [error_code, error_message] pairs, and the values
    # are a list of indexes of log entries that failed due to this error.
    #
    # A sample error looks like:
    # <Google::Cloud::PermissionDeniedError:
    #   message: 'User not authorized.',
    #   details: [
    #     <Google::Cloud::Logging::V2::WriteLogEntriesPartialErrors:
    #       log_entry_errors: {
    #         0 => <Google::Rpc::Status:
    #                code: 7,
    #                message: "User not authorized.",
    #                details: []>,
    #         1 => <Google::Rpc::Status:
    #                code: 3,
    #                message: "Log name contains illegal character :",
    #                details: []>,
    #         3 => <Google::Rpc::Status:
    #                code: 3,
    #                message: "Log name contains illegal character :",
    #                details: []>
    #       }
    #     >,
    #     <Google::Rpc::DebugInfo:
    #       stack_entries: [],
    #       detail: "..."
    #     >
    #   ]
    #   cause: <GRPC::PermissionDenied: 7:User not authorized.>
    # }
    #
    # The ultimate map that is constructed is:
    # {
    #   [7, 'User not authorized.']: [0],
    #   [3, 'Log name contains illegal character :']: [1, 3]
    # }
    def construct_error_details_map_grpc(gax_error)
      @log.error "construct_error_details_map_grpc: #{gax_error}"
      error_details_map = Hash.new { |h, k| h[k] = [] }
      error_details = ensure_array(gax_error.status_details)
      raise JSON::ParserError, 'The error details are empty.' if
        error_details.empty?
      raise JSON::ParserError, 'No partial error info in error details.' unless
        error_details[0].is_a?(
          Google::Cloud::Logging::V2::WriteLogEntriesPartialErrors
        )

      log_entry_errors = ensure_hash(error_details[0].log_entry_errors)
      log_entry_errors.each do |index, log_entry_error|
        error_key = [log_entry_error[:code], log_entry_error[:message]].freeze
        error_details_map[error_key] << index
      end
      error_details_map
    rescue JSON::ParserError => e
      @log.warn 'Failed to extract log entry errors from the error details:' \
                " #{gax_error.details.inspect}.", error: e
      {}
    end

    # Take a locally unique resource id and convert it to the globally unique
    # monitored resource.
    def monitored_resource_from_local_resource_id(local_resource_id)
      return unless
        /^
          (?<resource_type>k8s_container)
          \.(?<namespace_name>[0-9a-z-]+)
          \.(?<pod_name>[.0-9a-z-]+)
          \.(?<container_name>[0-9a-z-]+)$/x =~ local_resource_id ||
        /^
          (?<resource_type>k8s_pod)
          \.(?<namespace_name>[0-9a-z-]+)
          \.(?<pod_name>[.0-9a-z-]+)$/x =~ local_resource_id ||
        /^
          (?<resource_type>k8s_node)
          \.(?<node_name>[0-9a-z-]+)$/x =~ local_resource_id

      # Clear name and location if they're explicitly set to empty.
      @k8s_cluster_name = nil if @k8s_cluster_name == ''
      @k8s_cluster_location = nil if @k8s_cluster_location == ''

      begin
        @k8s_cluster_name ||= @utils.fetch_gce_metadata(
          @platform, 'instance/attributes/cluster-name'
        )
        @k8s_cluster_location ||= @utils.fetch_gce_metadata(
          @platform, 'instance/attributes/cluster-location'
        )
      rescue StandardError => e
        @log.error 'Failed to retrieve k8s cluster name and location.', \
                   error: e
      end
      case resource_type
      when K8S_CONTAINER_CONSTANTS[:resource_type]
        labels = {
          'namespace_name' => namespace_name,
          'pod_name' => pod_name,
          'container_name' => container_name,
          'cluster_name' => @k8s_cluster_name,
          'location' => @k8s_cluster_location
        }
        fallback_resource = GKE_CONSTANTS[:resource_type]
      when K8S_POD_CONSTANTS[:resource_type]
        labels = {
          'namespace_name' => namespace_name,
          'pod_name' => pod_name,
          'cluster_name' => @k8s_cluster_name,
          'location' => @k8s_cluster_location
        }
        fallback_resource = GKE_CONSTANTS[:resource_type]
      when K8S_NODE_CONSTANTS[:resource_type]
        labels = {
          'node_name' => node_name,
          'cluster_name' => @k8s_cluster_name,
          'location' => @k8s_cluster_location
        }
        fallback_resource = COMPUTE_CONSTANTS[:resource_type]
      end
      unless @k8s_cluster_name && @k8s_cluster_location
        @log.error "Failed to construct #{resource_type} resource locally." \
                   ' Falling back to writing logs against' \
                   " #{fallback_resource} resource.", error: e
        return
      end
      constructed_resource = Google::Apis::LoggingV2::MonitoredResource.new(
        type: resource_type,
        labels: labels
      )
      @log.debug("Constructed #{resource_type} resource locally: " \
                 "#{constructed_resource.inspect}")
      constructed_resource
    end

    # Convert the value to a Ruby array.
    def ensure_array(value)
      Array.try_convert(value) || (raise JSON::ParserError, value.class.to_s)
    end

    # Convert the value to a Ruby hash.
    def ensure_hash(value)
      Hash.try_convert(value) || (raise JSON::ParserError, value.class.to_s)
    end

    # Increment the metric for the number of successful requests.
    def increment_successful_requests_count
      return unless @successful_requests_count

      @successful_requests_count.increment(
        labels: { grpc: @use_grpc, code: @ok_code }
      )
    end

    # Increment the metric for the number of failed requests, labeled by
    # the provided status code.
    def increment_failed_requests_count(code)
      return unless @failed_requests_count

      @failed_requests_count.increment(
        labels: { grpc: @use_grpc, code: code }
      )
    end

    # Increment the metric for the number of log entries, successfully
    # ingested by the Stackdriver Logging API.
    def increment_ingested_entries_count(count)
      return unless @ingested_entries_count

      @ingested_entries_count.increment(
        labels: { grpc: @use_grpc, code: @ok_code }, by: count
      )
    end

    # Increment the metric for the number of log entries that were dropped
    # and not ingested by the Stackdriver Logging API.
    def increment_dropped_entries_count(count, code)
      return unless @dropped_entries_count

      @dropped_entries_count.increment(
        labels: { grpc: @use_grpc, code: code }, by: count
      )
    end

    # Increment the metric for the number of log entries that were dropped
    # and not ingested by the Stackdriver Logging API.
    def increment_retried_entries_count(count, code)
      return unless @retried_entries_count

      @retried_entries_count.increment(
        labels: { grpc: @use_grpc, code: code }, by: count
      )
    end
  end
end

module Google
  module Apis
    module LoggingV2
      # Override MonitoredResource::dup to make a deep copy.
      class MonitoredResource
        def dup
          ret = super
          ret.labels = labels.dup
          ret
        end
      end
    end
  end
end
