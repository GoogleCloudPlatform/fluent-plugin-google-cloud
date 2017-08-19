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

require_relative 'monitoring'

module Google
  module Protobuf
    # Alias the has_key? method to have the same interface as a regular map.
    class Map
      alias_method :key?, :has_key?
    end
  end
end

module Fluent
  # fluentd output plugin for the Stackdriver Logging API
  class GoogleCloudOutput < BufferedOutput
    # Constants for service names and resource types.
    module Constants
      APPENGINE_CONSTANTS = {
        service: 'appengine.googleapis.com',
        resource_type: 'gae_app',
        metadata_attributes: %w(gae_backend_name gae_backend_version).to_set
      }
      CLOUDFUNCTIONS_CONSTANTS = {
        service: 'cloudfunctions.googleapis.com',
        resource_type: 'cloud_function'
      }
      COMPUTE_CONSTANTS = {
        service: 'compute.googleapis.com',
        resource_type: 'gce_instance'
      }
      GKE_CONSTANTS = {
        service: 'container.googleapis.com',
        resource_type: 'container',
        extra_resource_labels: %w(namespace_id pod_id container_name),
        extra_common_labels: %w(namespace_name pod_name),
        metadata_attributes: %w(kube-env).to_set
      }
      DATAFLOW_CONSTANTS = {
        service: 'dataflow.googleapis.com',
        resource_type: 'dataflow_step',
        extra_common_labels: %w(region job_name job_id step_id)
      }
      DATAPROC_CONSTANTS = {
        service: 'cluster.dataproc.googleapis.com',
        resource_type: 'cloud_dataproc_cluster',
        metadata_attributes:
          %w(dataproc-cluster-uuid dataproc-cluster-name).to_set
      }
      EC2_CONSTANTS = {
        service: 'ec2.amazonaws.com',
        resource_type: 'aws_ec2_instance'
      }
      ML_CONSTANTS = {
        service: 'ml.googleapis.com',
        resource_type: 'ml_job',
        extra_common_labels: %w(job_id task_name)
      }

      # The map between a subservice name and a resource type.
      SUBSERVICE_MAP = \
        [APPENGINE_CONSTANTS, GKE_CONSTANTS, DATAFLOW_CONSTANTS,
         DATAPROC_CONSTANTS, ML_CONSTANTS]
        .map { |consts| [consts[:service], consts[:resource_type]] }.to_h
      # Default back to GCE if invalid value is detected.
      SUBSERVICE_MAP.default = COMPUTE_CONSTANTS[:resource_type]

      # The map between a resource type and expected subservice attributes.
      SUBSERVICE_METADATA_ATTRIBUTES = \
        [APPENGINE_CONSTANTS, GKE_CONSTANTS, DATAPROC_CONSTANTS]
        .map { |consts| [consts[:resource_type], consts[:metadata_attributes]] }
        .to_h

      # Default values for JSON payload keys to set the "trace",
      # "sourceLocation", "operation" and "labels" fields in the LogEntry.
      DEFAULT_PAYLOAD_KEY_PREFIX = 'logging.googleapis.com'
      DEFAULT_HTTP_REQUEST_KEY = 'httpRequest'
      DEFAULT_OPERATION_KEY = "#{DEFAULT_PAYLOAD_KEY_PREFIX}/operation"
      DEFAULT_SOURCE_LOCATION_KEY =
        "#{DEFAULT_PAYLOAD_KEY_PREFIX}/sourceLocation"
      DEFAULT_TRACE_KEY = "#{DEFAULT_PAYLOAD_KEY_PREFIX}/trace"

      # Map from each field name under LogEntry to corresponding variables
      # required to perform field value extraction from the log record.
      LOG_ENTRY_FIELDS_MAP = {
        'http_request' => [
          # The config to specify label name for field extraction from record.
          '@http_request_key',
          # Map from subfields' names to their types.
          [
            # subfield key in the payload, destination key, cast lambda (opt)
            %w(requestMethod request_method parse_string),
            %w(requestUrl request_url parse_string),
            %w(requestSize request_size parse_int),
            %w(status status parse_int),
            %w(responseSize response_size parse_int),
            %w(userAgent user_agent parse_string),
            %w(remoteIp remote_ip parse_string),
            %w(referer referer parse_string),
            %w(cacheHit cache_hit parse_bool),
            %w(cacheValidatedWithOriginServer
               cache_validated_with_origin_server parse_bool),
            %w(latency latency parse_latency)
          ],
          # The grpc version class name.
          'Google::Logging::Type::HttpRequest',
          # The non-grpc version class name.
          'Google::Apis::LoggingV2beta1::HttpRequest'
        ],
        'source_location' => [
          '@source_location_key',
          [
            %w(file file parse_string),
            %w(function function parse_string),
            %w(line line parse_int)
          ],
          'Google::Logging::V2::LogEntrySourceLocation',
          'Google::Apis::LoggingV2beta1::LogEntrySourceLocation'
        ],
        'operation' => [
          '@operation_key',
          [
            %w(id id parse_string),
            %w(producer producer parse_string),
            %w(first first parse_bool),
            %w(last last parse_bool)
          ],
          'Google::Logging::V2::LogEntryOperation',
          'Google::Apis::LoggingV2beta1::LogEntryOperation'
        ]
      }
    end

    include self::Constants

    Fluent::Plugin.register_output('google_cloud', self)

    PLUGIN_NAME = 'Fluentd Google Cloud Logging plugin'
    PLUGIN_VERSION = '0.6.6'

    # Name of the the Google cloud logging write scope.
    LOGGING_SCOPE = 'https://www.googleapis.com/auth/logging.write'

    # Address of the metadata service.
    METADATA_SERVICE_ADDR = '169.254.169.254'

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
    # These parameters override any values obtained from the metadata service.
    config_param :project_id, :string, :default => nil
    config_param :zone, :string, :default => nil
    config_param :vm_id, :string, :default => nil
    config_param :vm_name, :string, :default => nil

    # Map keys from a JSON payload to corresponding LogEntry fields.
    config_param :http_request_key, :string, :default =>
      DEFAULT_HTTP_REQUEST_KEY
    config_param :operation_key, :string, :default => DEFAULT_OPERATION_KEY
    config_param :source_location_key, :string, :default =>
      DEFAULT_SOURCE_LOCATION_KEY
    config_param :trace_key, :string, :default => DEFAULT_TRACE_KEY

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
    # component (Docker, Kubelet, etc.) logs from container logs.
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
    # Cloud Logging API.
    config_param :use_grpc, :bool, :default => false

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

    # Whether to collect metrics about the plugin usage. The mechanism for
    # collecting and exposing metrics is controlled by the monitoring_type
    # parameter.
    config_param :enable_monitoring, :bool, :default => false

    # What system to use when collecting metrics. Possible values are:
    #   - 'prometheus', in this case default registry in the Prometheus
    #     client library is used, without actually exposing the endpoint
    #     to serve metrics in the Prometheus format.
    #    - any other value will result in the absence of metrics.
    config_param :monitoring_type, :string,
                 :default => Monitoring::PrometheusMonitoringRegistry.name

    # rubocop:enable Style/HashSyntax

    # TODO: Add a log_name config option rather than just using the tag?

    # Expose attr_readers to make testing of metadata more direct than only
    # testing it indirectly through metadata sent with logs.
    attr_reader :project_id
    attr_reader :zone
    attr_reader :vm_id
    attr_reader :resource
    attr_reader :common_labels

    def initialize
      super
      # use the global logger
      @log = $log # rubocop:disable Style/GlobalVars
    end

    def configure(conf)
      super

      # If monitoring is enabled, register metrics in the default registry
      # and store metric objects for future use.
      if @enable_monitoring
        registry = Monitoring::MonitoringRegistryFactory.create @monitoring_type
        @successful_requests_count = registry.counter(
          :stackdriver_successful_requests_count,
          'A number of successful requests to the Stackdriver Logging API')
        @failed_requests_count = registry.counter(
          :stackdriver_failed_requests_count,
          'A number of failed requests to the Stackdriver Logging API,'\
            ' broken down by the error code')
        @ingested_entries_count = registry.counter(
          :stackdriver_ingested_entries_count,
          'A number of log entries ingested by Stackdriver Logging')
        @dropped_entries_count = registry.counter(
          :stackdriver_dropped_entries_count,
          'A number of log entries dropped by the Stackdriver output plugin')
      end

      # Alert on old authentication configuration.
      unless @auth_method.nil? && @private_key_email.nil? &&
             @private_key_path.nil? && @private_key_passphrase.nil?
        extra = []
        extra << 'auth_method' unless @auth_method.nil?
        extra << 'private_key_email' unless @private_key_email.nil?
        extra << 'private_key_path' unless @private_key_path.nil?
        extra << 'private_key_passphrase' unless @private_key_passphrase.nil?

        fail Fluent::ConfigError,
             "#{PLUGIN_NAME} no longer supports auth_method.\n" \
             'Please remove configuration parameters: ' +
               extra.join(' ')
      end

      set_regexp_patterns

      @platform = detect_platform

      # Set required variables: @project_id, @vm_id, @vm_name and @zone by
      # making some requests to metadata server.
      #
      # Note: Once we support metadata injection at Logging API side, we might
      # no longer need to require all these metadata in logging agent. But for
      # now, they are still required.
      #
      # TODO(qingling128): After Metadata Agent support is added, try extracting
      # these info from responses from Metadata Agent first.
      set_required_metadata_variables

      # Retrieve monitored resource.
      #
      # TODO(qingling128): After Metadata Agent support is added, try retrieving
      # the monitored resource from Metadata Agent first.
      @resource = determine_agent_level_monitored_resource_via_legacy

      # Set regexp that we should match tags against later on. Using a list
      # instead of a map to ensure order. For example, tags will be matched
      # against Cloud Functions first, then GKE.
      @tag_regexp_list = []
      if @resource.type == GKE_CONSTANTS[:resource_type]
        # We only support Cloud Functions logs for GKE right now.
        if fetch_gce_metadata('instance/attributes/'
                             ).split.include?('gcf_region')
          # Fetch this info and store it to avoid recurring
          # metadata server calls.
          @gcf_region = fetch_gce_metadata('instance/attributes/gcf_region')
          @tag_regexp_list << [
            CLOUDFUNCTIONS_CONSTANTS[:resource_type],
            @compiled_cloudfunctions_tag_regexp
          ]
        end
        @tag_regexp_list << [
          GKE_CONSTANTS[:resource_type], @compiled_kubernetes_tag_regexp
        ]
      end

      # Determine the common labels that should be added to all log entries
      # processed by this logging agent.
      @common_labels = determine_agent_level_common_labels

      # The resource and labels are now set up; ensure they can't be modified
      # without first duping them.
      @resource.freeze
      @resource.labels.freeze
      @common_labels.freeze

      # Log an informational message containing the Logs viewer URL
      @log.info 'Logs viewer address: https://console.cloud.google.com/logs/',
                "viewer?project=#{@project_id}&resource=#{@resource_type}/",
                "instance_id/#{@vm_id}"
    end

    def start
      super
      init_api_client
      @successful_call = false
      @timenanos_warning = false
    end

    def shutdown
      super
    end

    def write(chunk)
      # Group the entries since we have to make one call per tag.
      grouped_entries = {}
      chunk.msgpack_each do |tag, *arr|
        sanitized_tag = sanitize_tag(tag)
        if sanitized_tag.nil?
          @log.warn "Dropping log entries with invalid tag: '#{tag}'. " \
                    'A tag should be a string with utf8 characters.'
          next
        end
        grouped_entries[sanitized_tag] ||= []
        grouped_entries[sanitized_tag].push(arr)
      end

      grouped_entries.each do |tag, arr|
        entries = []
        group_resource, group_common_labels =
          determine_group_level_monitored_resource_and_labels(tag)

        arr.each do |time, record|
          next unless record.is_a?(Hash)

          extracted_resource_labels, extracted_common_labels = \
            determine_entry_level_labels(group_resource, record)
          entry_resource = group_resource.dup
          entry_resource.labels.merge!(extracted_resource_labels)
          entry_common_labels = \
            group_common_labels.merge(extracted_common_labels)

          is_json = false
          if @detect_json
            # Save the timestamp if available, then clear it out to allow for
            # determining whether we should parse the log or message field.
            timestamp = record.delete('time')
            # If the log is json, we want to export it as a structured log
            # unless there is additional metadata that would be lost.
            record_json = nil
            if record.length == 1
              %w(log message msg).each do |field|
                if record.key?(field)
                  record_json = parse_json_or_nil(record[field])
                end
              end
            end
            unless record_json.nil?
              record = record_json
              is_json = true
            end
            # Restore timestamp if necessary.
            unless record.key?('time') || timestamp.nil?
              record['time'] = timestamp
            end
          end

          ts_secs, ts_nanos = compute_timestamp(
            entry_resource.type, record, time)
          severity = compute_severity(
            entry_resource.type, record, entry_common_labels)

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
          if @use_grpc
            entry = Google::Logging::V2::LogEntry.new(
              labels: entry_common_labels,
              resource: Google::Api::MonitoredResource.new(
                type: entry_resource.type,
                labels: entry_resource.labels.to_h
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
          else
            # Remove the labels if we didn't populate them with anything.
            entry_resource.labels = nil if entry_resource.labels.empty?
            entry = Google::Apis::LoggingV2beta1::LogEntry.new(
              labels: entry_common_labels,
              resource: entry_resource,
              severity: severity,
              timestamp: {
                seconds: ts_secs,
                nanos: ts_nanos
              }
            )
          end

          # Get fully-qualified trace id for LogEntry "trace" field per config.
          fq_trace_id = record.delete(@trace_key)
          entry.trace = fq_trace_id if fq_trace_id

          set_log_entry_fields(record, entry)

          set_payload(entry_resource.type, record, entry, is_json)

          entries.push(entry)
        end
        # Don't send an empty request if we rejected all the entries.
        next if entries.empty?

        log_name = "projects/#{@project_id}/logs/#{log_name(
          tag, group_resource)}"

        # Does the actual write to the cloud logging api.
        client = api_client
        if @use_grpc
          begin
            labels_utf8_pairs = group_common_labels.map do |k, v|
              [k.encode('utf-8'), convert_to_utf8(v)]
            end

            write_request = Google::Logging::V2::WriteLogEntriesRequest.new(
              log_name: log_name,
              resource: Google::Api::MonitoredResource.new(
                type: group_resource.type,
                labels: group_resource.labels.to_h
              ),
              labels: labels_utf8_pairs.to_h,
              entries: entries
            )

            client.write_log_entries(write_request)
            increment_successful_requests_count
            increment_ingested_entries_count(entries.length)

            # Let the user explicitly know when the first call succeeded,
            # to aid with verification and troubleshooting.
            unless @successful_call
              @successful_call = true
              @log.info 'Successfully sent gRPC to Stackdriver Logging API.'
            end

          rescue GRPC::Cancelled => error
            increment_failed_requests_count(GRPC::Core::StatusCodes::CANCELLED)
            # RPC cancelled, so retry via re-raising the error.
            raise error

          rescue GRPC::BadStatus => error
            increment_failed_requests_count(error.code)
            case error.code
            when GRPC::Core::StatusCodes::CANCELLED,
                 GRPC::Core::StatusCodes::UNAVAILABLE,
                 GRPC::Core::StatusCodes::DEADLINE_EXCEEDED,
                 GRPC::Core::StatusCodes::INTERNAL,
                 GRPC::Core::StatusCodes::UNKNOWN
              # TODO
              # Server error, so retry via re-raising the error.
              raise error
            when GRPC::Core::StatusCodes::UNIMPLEMENTED,
                 GRPC::Core::StatusCodes::RESOURCE_EXHAUSTED
              # Most client errors indicate a problem with the request itself
              # and should not be retried.
              dropped = entries.length
              increment_dropped_entries_count(dropped)
              @log.warn "Dropping #{dropped} log message(s)",
                        error: error.to_s, error_code: error.code.to_s
            when GRPC::Core::StatusCodes::UNAUTHENTICATED
              # Authorization error.
              # These are usually solved via a `gcloud auth` call, or by
              # modifying the permissions on the Google Cloud project.
              dropped = entries.length
              increment_dropped_entries_count(dropped)
              @log.warn "Dropping #{dropped} log message(s)",
                        error: error.to_s, error_code: error.code.to_s
            else
              # Assume this is a problem with the request itself
              # and don't retry.
              dropped = entries.length
              increment_dropped_entries_count(dropped)
              @log.error "Unknown response code #{error.code} from the "\
                         "server, dropping #{dropped} log message(s)",
                         error: error.to_s, error_code: error.code.to_s
            end
          end
        else
          begin
            write_request = \
              Google::Apis::LoggingV2beta1::WriteLogEntriesRequest.new(
                log_name: log_name,
                resource: group_resource,
                labels: group_common_labels,
                entries: entries)

            # TODO: RequestOptions
            begin
              client.write_entry_log_entries(write_request)
            rescue Google::Apis::Error => error
              increment_failed_requests_count(error.status_code)
              raise error
            end
            increment_successful_requests_count
            increment_ingested_entries_count(entries.length)

            # Let the user explicitly know when the first call succeeded,
            # to aid with verification and troubleshooting.
            unless @successful_call
              @successful_call = true
              @log.info 'Successfully sent to Stackdriver Logging API.'
            end

          rescue Google::Apis::ServerError => error
            # Server error, so retry via re-raising the error.
            raise error

          rescue Google::Apis::AuthorizationError => error
            # Authorization error.
            # These are usually solved via a `gcloud auth` call, or by modifying
            # the permissions on the Google Cloud project.
            dropped = entries.length
            increment_dropped_entries_count(dropped)
            @log.warn "Dropping #{dropped} log message(s)",
                      error_class: error.class.to_s, error: error.to_s

          rescue Google::Apis::ClientError => error
            # Most ClientErrors indicate a problem with the request itself and
            # should not be retried.
            dropped = entries.length
            increment_dropped_entries_count(dropped)
            @log.warn "Dropping #{dropped} log message(s)",
                      error_class: error.class.to_s, error: error.to_s
          end
        end
      end
    end

    private

    def parse_json_or_nil(input)
      # Only here to please rubocop...
      return nil if input.nil?

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
          break unless c == 9 || c == 10 || c == 13 || c == 32
        end # case
      end # do
      nil
    end

    # "enum" of Platform values
    module Platform
      OTHER = 0  # Other/unkown platform
      GCE = 1    # Google Compute Engine
      EC2 = 2    # Amazon EC2
    end

    # Determine what platform we are running on by consulting the metadata
    # service (unless the user has explicitly disabled using that).
    def detect_platform
      unless @use_metadata_service
        @log.info 'use_metadata_service is false; not detecting platform'
        return Platform::OTHER
      end

      begin
        open('http://' + METADATA_SERVICE_ADDR) do |f|
          if f.meta['metadata-flavor'] == 'Google'
            @log.info 'Detected GCE platform'
            return Platform::GCE
          end
          if f.meta['server'] == 'EC2ws'
            @log.info 'Detected EC2 platform'
            return Platform::EC2
          end
        end
      rescue StandardError => e
        @log.error 'Failed to access metadata service: ', error: e
      end

      @log.info 'Unable to determine platform'
      Platform::OTHER
    end

    def fetch_gce_metadata(metadata_path)
      fail "Called fetch_gce_metadata with platform=#{@platform}" unless
        @platform == Platform::GCE
      # See https://cloud.google.com/compute/docs/metadata
      open('http://' + METADATA_SERVICE_ADDR + '/computeMetadata/v1/' +
           metadata_path, 'Metadata-Flavor' => 'Google', &:read)
    end

    # EC2 Metadata server returns everything in one call. Store it after the
    # first fetch to avoid making multiple calls.
    def ec2_metadata
      fail "Called ec2_metadata with platform=#{@platform}" unless
        @platform == Platform::EC2
      unless @ec2_metadata
        # See http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
        open('http://' + METADATA_SERVICE_ADDR +
             '/latest/dynamic/instance-identity/document') do |f|
          contents = f.read
          @ec2_metadata = JSON.parse(contents)
        end
      end

      @ec2_metadata
    end

    # Set regexp patterns to parse tags and logs.
    def set_regexp_patterns
      @compiled_kubernetes_tag_regexp = Regexp.new(@kubernetes_tag_regexp) if
        @kubernetes_tag_regexp

      @compiled_cloudfunctions_tag_regexp =
        /\.(?<encoded_function_name>.+)\.\d+-[^-]+_default_worker$/
      @compiled_cloudfunctions_log_regexp = /^
        (?:\[(?<severity>.)\])?
        \[(?<timestamp>.{24})\]
        (?:\[(?<execution_id>[^\]]+)\])?
        [ ](?<text>.*)$/x

      @compiled_http_latency_regexp =
        /^\s*(?<seconds>\d+)(?<decimal>\.\d+)?\s*s\s*$/
    end

    # Set required variables like @project_id, @vm_id, @vm_name and @zone.
    def set_required_metadata_variables
      set_project_id
      set_vm_id
      set_vm_name
      set_location

      # All metadata parameters must now be set.
      missing = []
      missing << 'project_id' unless @project_id
      missing << 'zone' unless @zone
      missing << 'vm_id' unless @vm_id
      return if missing.empty?
      fail Fluent::ConfigError, 'Unable to obtain metadata parameters: ' +
        missing.join(' ')
    end

    # 1. Return the value if it is explicitly set in the config already.
    # 2. If not, try to retrieve it by calling metadata server directly.
    # 3. If still not set, try to obtain it from the credentials.
    def set_project_id
      @project_id ||= fetch_gce_metadata('project/project-id') if
        @platform == Platform::GCE
      @project_id ||= CredentialsInfo.project_id
    rescue StandardError => e
      @log.error 'Failed to obtain project id: ', error: e
    end

    # 1. Return the value if it is explicitly set in the config already.
    # 2. If not, try to retrieve it by calling metadata servers directly.
    def set_vm_id
      @vm_id ||= fetch_gce_metadata('instance/id') if @platform == Platform::GCE
      @vm_id ||= ec2_metadata['instanceId'] if @platform == Platform::EC2
    rescue StandardError => e
      @log.error 'Failed to obtain vm_id: ', error: e
    end

    # 1. Return the value if it is explicitly set in the config already.
    # 2. If not, try to retrieve it locally.
    def set_vm_name
      @vm_name ||= Socket.gethostname
    rescue StandardError => e
      @log.error 'Failed to obtain vm name: ', error: e
    end

    # 1. Return the value if it is explicitly set in the config already.
    # 2. If not, try to retrieve it locally.
    def set_location
      # Response format: "projects/<number>/zones/<zone>"
      @zone ||= fetch_gce_metadata('instance/zone').rpartition('/')[2] if
        @platform == Platform::GCE
      @zone ||= 'aws:' + ec2_metadata['availabilityZone'] if
        @platform == Platform::EC2 && ec2_metadata.key?('availabilityZone')
    rescue StandardError => e
      @log.error 'Failed to obtain location: ', error: e
    end

    # Retrieve monitored resource via the legacy way.
    #
    # TODO(qingling128): Use this as only a fallback plan after Metadata Agent
    # support is added.
    def determine_agent_level_monitored_resource_via_legacy
      resource = Google::Apis::LoggingV2beta1::MonitoredResource.new(
        labels: {})
      resource.type = determine_agent_level_monitored_resource_type
      resource.labels = determine_agent_level_monitored_resource_labels(
        resource.type)
      resource
    end

    # Determine agent level monitored resource type.
    def determine_agent_level_monitored_resource_type
      case @platform
      when Platform::OTHER
        # Unknown platform will be defaulted to GCE instance.
        return COMPUTE_CONSTANTS[:resource_type]

      when Platform::EC2
        return EC2_CONSTANTS[:resource_type]

      when Platform::GCE
        # Resource types determined by @subservice_name config.
        return SUBSERVICE_MAP[@subservice_name] if @subservice_name

        # Resource types determined by @detect_subservice config.
        if @detect_subservice
          begin
            attributes = fetch_gce_metadata('instance/attributes/').split.to_set
            SUBSERVICE_METADATA_ATTRIBUTES.each do |resource_type, expected|
              return resource_type if attributes.superset?(expected)
            end
          rescue StandardError => e
            @log.error 'Failed to detect subservice: ', error: e
          end
        end

        # GCE instance.
        return COMPUTE_CONSTANTS[:resource_type]
      end
    end

    # Determine agent level monitored resource labels based on the resource
    # type. Each resource type has its own labels that need to be filled in.
    def determine_agent_level_monitored_resource_labels(type)
      case type
      # GAE app.
      when APPENGINE_CONSTANTS[:resource_type]
        return {
          'module_id' =>
            fetch_gce_metadata('instance/attributes/gae_backend_name'),
          'version_id' =>
            fetch_gce_metadata('instance/attributes/gae_backend_version')
        }

      # GCE.
      when COMPUTE_CONSTANTS[:resource_type]
        return {
          'instance_id' => @vm_id,
          'zone' => @zone
        }

      # GKE container.
      when GKE_CONSTANTS[:resource_type]
        raw_kube_env = fetch_gce_metadata('instance/attributes/kube-env')
        kube_env = YAML.load(raw_kube_env)
        return {
          'instance_id' => @vm_id,
          'zone' => @zone,
          'cluster_name' => cluster_name_from_kube_env(kube_env)
        }

      # Cloud Dataproc.
      when DATAPROC_CONSTANTS[:resource_type]
        return {
          'cluster_uuid' =>
            fetch_gce_metadata('instance/attributes/dataproc-cluster-uuid'),
          'cluster_name' =>
            fetch_gce_metadata('instance/attributes/dataproc-cluster-name'),
          'region' =>
            fetch_gce_metadata('instance/attributes/dataproc-region')
        }

      # EC2.
      when EC2_CONSTANTS[:resource_type]
        labels = {
          'instance_id' => @vm_id,
          'region' => @zone
        }
        labels['aws_account'] = ec2_metadata['accountId'] if
          ec2_metadata.key?('accountId')
        return labels
      end

      {}
    rescue StandardError => e
      @log.error "Failed to set monitored resource labels for #{type}: ",
                 error: e
      return {}
    end

    # Determine the common labels that should be added to all log entries
    # processed by this logging agent.
    def determine_agent_level_common_labels
      labels = {}
      # User can specify labels via config. We want to capture those as well.
      labels.merge!(@labels) if @labels

      case @resource.type
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
        labels.merge!(
          "#{COMPUTE_CONSTANTS[:service]}/resource_name" => @vm_name)

      # EC2.
      when EC2_CONSTANTS[:resource_type]
        labels.merge!(
          "#{EC2_CONSTANTS[:service]}/resource_name" => @vm_name)
      end
      labels
    end

    # Determine the group level monitored resource and common labels shared by a
    # collection of entries.
    def determine_group_level_monitored_resource_and_labels(tag)
      # Determine group level monitored resource type. For certain types,
      # extract useful info from the tag and store those in
      # matched_regex_group.
      group_resource_type, matched_regex_group =
        determine_group_level_monitored_resource_type(tag)

      # Determine group level monitored resource labels and common labels.
      group_resource_labels, group_common_labels =
        determine_group_level_labels(group_resource_type, matched_regex_group)

      group_resource = Google::Apis::LoggingV2beta1::MonitoredResource.new(
        type: group_resource_type,
        labels: group_resource_labels.to_h
      )

      # Freeze the per-request state. Any further changes must be made on a
      # per-entry basis.
      group_resource.freeze
      group_resource.labels.freeze
      group_common_labels.freeze

      [group_resource, group_common_labels]
    end

    # Determine group level monitored resource type shared by a collection of
    # entries.
    # Return the resource type and tag regexp matched groups. The matched groups
    # only apply to some resource types. Return nil if not applicable or if
    # there is no match.
    def determine_group_level_monitored_resource_type(tag)
      @tag_regexp_list.each do |derived_type, tag_regexp|
        matched_regex_group = tag_regexp.match(tag)
        return [derived_type, matched_regex_group] if
          matched_regex_group
      end
      [@resource.type, nil]
    end

    # Determine group level monitored resource labels and common labels. These
    # labels will be shared by a collection of entries.
    def determine_group_level_labels(group_resource_type, matched_regex_group)
      group_resource_labels = @resource.labels.dup
      group_common_labels = @common_labels.dup

      case group_resource_type
      # Cloud Functions.
      when CLOUDFUNCTIONS_CONSTANTS[:resource_type]
        group_resource_labels.merge!(
          'region' => @gcf_region,
          'function_name' => decode_cloudfunctions_function_name(
            matched_regex_group['encoded_function_name'])
        )

        instance_id = group_resource_labels.delete('instance_id')
        group_common_labels.merge!(
          "#{GKE_CONSTANTS[:service]}/instance_id" => instance_id,
          "#{COMPUTE_CONSTANTS[:service]}/resource_id" => instance_id,
          "#{GKE_CONSTANTS[:service]}/cluster_name" =>
            group_resource_labels.delete('cluster_name'),
          "#{COMPUTE_CONSTANTS[:service]}/zone" =>
            group_resource_labels.delete('zone')
        )

      # GKE container.
      when GKE_CONSTANTS[:resource_type]
        if matched_regex_group
          # We only expect one occurrence of each key in the match group.
          resource_labels_candidates =
            matched_regex_group.names.zip(matched_regex_group.captures).to_h
          common_labels_candidates =
            resource_labels_candidates.dup
          group_resource_labels.merge!(
            delete_and_extract_labels(
              resource_labels_candidates,
              # The kubernetes_tag_regexp is poorly named. 'namespace_name' is
              # in fact 'namespace_id'. 'pod_name' is in fact 'pod_id'.
              # TODO(qingling128): Figure out how to put this map into
              # constants like GKE_CONSTANTS[:extra_resource_labels].
              'container_name' => 'container_name',
              'namespace_name' => 'namespace_id',
              'pod_name' => 'pod_id'))

          group_common_labels.merge!(
            delete_and_extract_labels(
              common_labels_candidates,
              GKE_CONSTANTS[:extra_common_labels]
                .map { |l| [l, "#{GKE_CONSTANTS[:service]}/#{l}"] }.to_h))
        end
      end

      [group_resource_labels, group_common_labels]
    end

    # Extract entry resource and common labels that should be applied to
    # individual entries from the group resource.
    def determine_entry_level_labels(group_resource, record)
      resource_labels = {}
      common_labels = {}

      # Cloud Functions.
      if group_resource.type == CLOUDFUNCTIONS_CONSTANTS[:resource_type] &&
         record.key?('log')
        @cloudfunctions_log_match =
          @compiled_cloudfunctions_log_regexp.match(record['log'])
        common_labels['execution_id'] =
          @cloudfunctions_log_match['execution_id'] if \
            @cloudfunctions_log_match &&
            @cloudfunctions_log_match['execution_id']
      end

      # GKE containers.
      if group_resource.type == GKE_CONSTANTS[:resource_type]
        # Move the stdout/stderr annotation from the record into a label.
        common_labels.merge!(
          delete_and_extract_labels(
            record, 'stream' => "#{GKE_CONSTANTS[:service]}/stream"))

        # If the record has been annotated by the kubernetes_metadata_filter
        # plugin, then use that metadata. Otherwise, rely on commonLabels
        # populated at the grouped_entries level from the group's tag.
        if record.key?('kubernetes')
          resource_labels.merge!(
            delete_and_extract_labels(
              record['kubernetes'], GKE_CONSTANTS[:extra_resource_labels]
                .map { |l| [l, l] }.to_h))
          common_labels.merge!(
            delete_and_extract_labels(
              record['kubernetes'], GKE_CONSTANTS[:extra_common_labels]
                .map { |l| [l, "#{GKE_CONSTANTS[:service]}/#{l}"] }.to_h))
          # Prepend label/ to all user-defined labels' keys.
          if record['kubernetes'].key?('labels')
            common_labels.merge!(
              delete_and_extract_labels(
                record['kubernetes']['labels'], record['kubernetes']['labels']
                  .map { |key, _| [key, "label/#{key}"] }.to_h))
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
      # These labels can be set via configuring 'labels' or 'label_map'.
      # Report them as monitored resource labels instead of common labels.
      # e.g. "dataflow.googleapis.com/job_id" => "job_id"
      [DATAFLOW_CONSTANTS, ML_CONSTANTS].each do |service_constants|
        next unless group_resource.type == service_constants[:resource_type]
        resource_labels.merge!(
          delete_and_extract_labels(
            common_labels, service_constants[:extra_common_labels]
              .map { |l| ["#{service_constants[:service]}/#{l}", l] }.to_h))
      end

      [resource_labels, common_labels]
    end

    # TODO: This functionality should eventually be available in another
    # library, but implement it ourselves for now.
    module CredentialsInfo
      # Determine the project ID from the credentials, if possible.
      # Returns the project ID (as a string) on success, or nil on failure.
      def self.project_id
        creds = Google::Auth.get_application_default(LOGGING_SCOPE)
        if creds.issuer
          id = extract_project_id(creds.issuer)
          return id unless id.nil?
        end
        if creds.client_id
          id = extract_project_id(creds.client_id)
          return id unless id.nil?
        end
        nil
      end

      # Extracts the project id (either name or number) from str and returns
      # it (as a string) on success, or nil on failure.
      #
      # Recognizes IAM format (account@project-name.iam.gserviceaccount.com)
      # as well as the legacy format with a project number at the front of the
      # string, terminated by a dash (-) which is not part of the ID, i.e.:
      # 270694816269-1l1r2hb813leuppurdeik0apglbs80sv.apps.googleusercontent.com
      def self.extract_project_id(str)
        [/^.*@(?<project_id>.+)\.iam\.gserviceaccount\.com/,
         /^(?<project_id>\d+)-/].each do |exp|
          match_data = exp.match(str)
          return match_data['project_id'] unless match_data.nil?
        end
        nil
      end
    end

    def cluster_name_from_kube_env(kube_env)
      return kube_env['CLUSTER_NAME'] if kube_env.key?('CLUSTER_NAME')
      instance_prefix = kube_env['INSTANCE_PREFIX']
      gke_name_match = /^gke-(.+)-[0-9a-f]{8}$/.match(instance_prefix)
      return gke_name_match.captures[0] if gke_name_match &&
                                           !gke_name_match.captures.empty?
      instance_prefix
    end

    def compute_timestamp(resource_type, record, time)
      if record.key?('timestamp') &&
         record['timestamp'].is_a?(Hash) &&
         record['timestamp'].key?('seconds') &&
         record['timestamp'].key?('nanos')
        ts_secs = record['timestamp']['seconds']
        ts_nanos = record['timestamp']['nanos']
        record.delete('timestamp')
      elsif record.key?('timestampSeconds') &&
            record.key?('timestampNanos')
        ts_secs = record.delete('timestampSeconds')
        ts_nanos = record.delete('timestampNanos')
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
      elsif resource_type == CLOUDFUNCTIONS_CONSTANTS[:resource_type] &&
            @cloudfunctions_log_match
        timestamp = DateTime.parse(@cloudfunctions_log_match['timestamp'])
        ts_secs = timestamp.strftime('%s').to_i
        ts_nanos = timestamp.strftime('%N').to_i
      elsif record.key?('time')
        # k8s ISO8601 timestamp
        begin
          timestamp = Time.iso8601(record.delete('time'))
        rescue
          timestamp = Time.at(time)
        end
        ts_secs = timestamp.tv_sec
        ts_nanos = timestamp.tv_nsec
      else
        timestamp = Time.at(time)
        ts_secs = timestamp.tv_sec
        ts_nanos = timestamp.tv_nsec
      end
      [ts_secs, ts_nanos]
    end

    def compute_severity(resource_type, record, entry_common_labels)
      if resource_type == CLOUDFUNCTIONS_CONSTANTS[:resource_type]
        if @cloudfunctions_log_match && @cloudfunctions_log_match['severity']
          return parse_severity(@cloudfunctions_log_match['severity'])
        elsif record.key?('stream') && record['stream'] == 'stdout'
          record.delete('stream')
          return 'INFO'
        elsif record.key?('stream') && record['stream'] == 'stderr'
          record.delete('stream')
          return 'ERROR'
        else
          return 'DEFAULT'
        end
      elsif record.key?('severity')
        return parse_severity(record.delete('severity'))
      elsif resource_type == GKE_CONSTANTS[:resource_type] &&
            entry_common_labels.key?("#{GKE_CONSTANTS[:service]}/stream")
        stream = entry_common_labels["#{GKE_CONSTANTS[:service]}/stream"]
        if stream == 'stdout'
          return 'INFO'
        elsif stream == 'stderr'
          return 'ERROR'
        else
          return 'DEFAULT'
        end
      else
        return 'DEFAULT'
      end
    end

    def set_log_entry_fields(record, entry)
      LOG_ENTRY_FIELDS_MAP.each do |field_name, config|
        payload_key, subfields, grpc_class, non_grpc_class = config
        begin
          payload_key = instance_variable_get(payload_key)
          fields = record[payload_key]
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

          if @use_grpc
            output = Object.const_get(grpc_class).new
          else
            output = Object.const_get(non_grpc_class).new
          end
          extracted_subfields.each do |key, value|
            output.send("#{key}=", value)
          end

          record.delete(payload_key) if fields.empty?

          entry.send("#{field_name}=", output)
        rescue StandardError => err
          @log.error "Failed to set log entry field for #{field_name}.", err
        end
      end
    end

    # Values permitted by the API for 'severity' (which is an enum).
    VALID_SEVERITIES = Set.new(
      %w(DEFAULT DEBUG INFO NOTICE WARNING ERROR CRITICAL ALERT EMERGENCY))

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
      'ERR' => 'ERROR',
      'F' => 'CRITICAL'
    }

    def parse_severity(severity_str)
      # The API is case insensitive, but uppercase to make things simpler.
      severity = severity_str.upcase.strip

      # If the severity is already valid, just return it.
      return severity if VALID_SEVERITIES.include?(severity)

      # If the severity is an integer (string) return it as an integer,
      # truncated to the closest valid value (multiples of 100 between 0-800).
      if /\A\d+\z/.match(severity)
        begin
          numeric_severity = (severity.to_i / 100) * 100
          if numeric_severity < 0
            return 0
          elsif numeric_severity > 800
            return 800
          else
            return numeric_severity
          end
        rescue
          return 'DEFAULT'
        end
      end

      # Try to translate the severity.
      if SEVERITY_TRANSLATIONS.key?(severity)
        return SEVERITY_TRANSLATIONS[severity]
      end

      # If all else fails, use 'DEFAULT'.
      'DEFAULT'
    end

    GRPC_SEVERITY_MAPPING = {
      'DEFAULT' => Google::Logging::Type::LogSeverity::DEFAULT,
      'DEBUG' => Google::Logging::Type::LogSeverity::DEBUG,
      'INFO' => Google::Logging::Type::LogSeverity::INFO,
      'NOTICE' => Google::Logging::Type::LogSeverity::NOTICE,
      'WARNING' => Google::Logging::Type::LogSeverity::WARNING,
      'ERROR' => Google::Logging::Type::LogSeverity::ERROR,
      'CRITICAL' => Google::Logging::Type::LogSeverity::CRITICAL,
      'ALERT' => Google::Logging::Type::LogSeverity::ALERT,
      'EMERGENCY' => Google::Logging::Type::LogSeverity::EMERGENCY,
      0 => Google::Logging::Type::LogSeverity::DEFAULT,
      100 => Google::Logging::Type::LogSeverity::DEBUG,
      200 => Google::Logging::Type::LogSeverity::INFO,
      300 => Google::Logging::Type::LogSeverity::NOTICE,
      400 => Google::Logging::Type::LogSeverity::WARNING,
      500 => Google::Logging::Type::LogSeverity::ERROR,
      600 => Google::Logging::Type::LogSeverity::CRITICAL,
      700 => Google::Logging::Type::LogSeverity::ALERT,
      800 => Google::Logging::Type::LogSeverity::EMERGENCY
    }

    def grpc_severity(severity)
      # TODO: find out why this doesn't work.
      # if severity.is_a? String
      #   return Google::Logging::Type::LogSeverity.resolve(severity)
      # end
      if GRPC_SEVERITY_MAPPING.key?(severity)
        return GRPC_SEVERITY_MAPPING[severity]
      end
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
        return Google::Protobuf::Duration.new(
          seconds: seconds,
          nanos: nanos
        )
      else
        return {
          seconds: seconds,
          nanos: nanos
        }.delete_if { |_, v| v == 0 }
      end
    end

    def decode_cloudfunctions_function_name(function_name)
      function_name.gsub(/c\.[a-z]/) { |s| s.upcase[-1] }
        .gsub('u.u', '_').gsub('d.d', '$').gsub('a.a', '@').gsub('p.p', '.')
    end

    def format(tag, time, record)
      [tag, time, record].to_msgpack
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
        extracted_labels[new_label] =
          convert_to_utf8(hash.delete(original_label).to_s) if
            hash.key?(original_label)
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
        fail Google::Protobuf::Error, "Unknown type: #{value.class}"
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

    def set_payload(resource_type, record, entry, is_json)
      # Only one of {text_payload, json_payload} will be set.
      text_payload = nil
      json_payload = nil
      # If this is a Cloud Functions log that matched the expected regexp,
      # use text payload. Otherwise, use JSON if we found valid JSON, or text
      # payload in the following cases:
      # 1. This is a Cloud Functions log and the 'log' key is available
      # 2. This is an unstructured Container log and the 'log' key is available
      # 3. The only remaining key is 'message'
      if resource_type == CLOUDFUNCTIONS_CONSTANTS[:resource_type] &&
         @cloudfunctions_log_match
        text_payload = @cloudfunctions_log_match['text']
      elsif resource_type == CLOUDFUNCTIONS_CONSTANTS[:resource_type] &&
            record.key?('log')
        text_payload = record['log']
      elsif is_json
        json_payload = record
      elsif resource_type == GKE_CONSTANTS[:resource_type] &&
            record.key?('log')
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
        entry.text_payload = if @use_grpc
                               convert_to_utf8(text_payload)
                             else
                               text_payload
                             end
      end
    end

    def log_name(tag, resource)
      if resource.type == CLOUDFUNCTIONS_CONSTANTS[:resource_type]
        tag = 'cloud-functions'
      elsif resource.type == APPENGINE_CONSTANTS[:resource_type]
        # Add a prefix to Managed VM logs to prevent namespace collisions.
        tag = "#{APPENGINE_CONSTANTS[:service]}/#{tag}"
      elsif resource.type == GKE_CONSTANTS[:resource_type]
        # For Kubernetes logs, use just the container name as the log name
        # if we have it.
        if resource.labels && resource.labels.key?('container_name')
          sanitized_tag = sanitize_tag(resource.labels['container_name'])
          tag = sanitized_tag unless sanitized_tag.nil?
        end
      end
      tag = ERB::Util.url_encode(tag)
      tag
    end

    def init_api_client
      return if @use_grpc
      # TODO: Use a non-default ClientOptions object.
      Google::Apis::ClientOptions.default.application_name = PLUGIN_NAME
      Google::Apis::ClientOptions.default.application_version = PLUGIN_VERSION
      @client = Google::Apis::LoggingV2beta1::LoggingService.new
      @client.authorization = Google::Auth.get_application_default(
        LOGGING_SCOPE)
    end

    def api_client
      if @use_grpc
        ssl_creds = GRPC::Core::ChannelCredentials.new
        authentication = Google::Auth.get_application_default
        creds = GRPC::Core::CallCredentials.new(authentication.updater_proc)
        creds = ssl_creds.compose(creds)
        @client = Google::Logging::V2::LoggingServiceV2::Stub.new(
          'logging.googleapis.com', creds)
      else
        unless @client.authorization.expired?
          begin
            @client.authorization.fetch_access_token!
          rescue MultiJson::ParseError
            # Workaround an issue in the API client; just re-raise a more
            # descriptive error for the user (which will still cause a retry).
            raise Google::APIClient::ClientError, 'Unable to fetch access ' \
              'token (no scopes configured?)'
          end
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
          replace: @non_utf8_replacement_string)
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

    # Increment the metric for the number of successful requests.
    def increment_successful_requests_count
      return unless @successful_requests_count
      @successful_requests_count.increment(grpc: @use_grpc)
    end

    # Increment the metric for the number of failed requests, labeled by
    # the provided status code.
    def increment_failed_requests_count(code)
      return unless @failed_requests_count
      @failed_requests_count.increment(grpc: @use_grpc, code: code)
    end

    # Increment the metric for the number of log entries, successfully
    # ingested by the Stackdriver Logging API.
    def increment_ingested_entries_count(count)
      return unless @ingested_entries_count
      @ingested_entries_count.increment({}, count)
    end

    # Increment the metric for the number of log entries that were dropped
    # and not ingested by the Stackdriver Logging API.
    def increment_dropped_entries_count(count)
      return unless @dropped_entries_count
      @dropped_entries_count.increment({}, count)
    end
  end
end

module Google
  module Apis
    module LoggingV2beta1
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
