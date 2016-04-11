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
require 'json'
require 'google/apis'
require 'google/apis/logging_v1beta3'
require 'fluent/plugin/google_util'

module Fluent
  # fluentd output plugin for the Google Cloud Logging API
  class GoogleCloudOutput < BufferedOutput
    Fluent::Plugin.register_output('google_cloud', self)

    # Use the GoogleUtil mixins for metadata and credential management.
    include Fluent::GoogleUtil::MetadataMixin
    include Fluent::GoogleUtil::CredentialsMixin

    PLUGIN_NAME = 'Fluentd Google Cloud Logging plugin'
    PLUGIN_VERSION = '0.4.16'

    # Name of the the Google cloud logging write scope.
    LOGGING_SCOPE = 'https://www.googleapis.com/auth/logging.write'

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

    # Whether to try to detect of the VM is owned by a "subservice" such as App
    # Engine of Kubernetes, rather than just associating the logs with the
    # compute service of the platform. This currently only has any effect when
    # running on GCE.
    # The initial motivation for this is to separate out Kubernetes node
    # component (Docker, Kubelet, etc.) logs from container logs.
    config_param :detect_subservice, :bool, :default => true

    # The regular expression to use on Kubernetes logs to extract some basic
    # information about the log source. The regex must contain capture groups
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

    # Credentials and Authorization
    #
    # Method 1: Use Application Default Credentials / GCE service account
    #
    # This method makes use of the application default credentials. These
    # are provided by GCE, or through the the 'gcloud auth' command.
    # This requires no parameters, though it may read credentials
    # located by the environment variable GOOGLE_APPLICATION_CREDENTIALS.
    #
    # Method 2: Use Service account keys.
    #
    # service_credentials_path is a path to a service account key file,
    # in json format, which can be acquired from the Google Cloud Developers
    # Console. When set, the other fields are unnecessary.
    config_param :service_credentials_path, :string, :default => nil

    # DEPRECATED: The following parameters, if present in the config
    # indicate that the plugin configuration must be updated.
    config_param :auth_method, :string, :default => nil
    config_param :private_key_email, :string, :default => nil
    config_param :private_key_path, :string, :default => nil
    config_param :private_key_passphrase, :string,
                 :default => nil,
                 :secret => true

    # rubocop:enable Style/HashSyntax

    # TODO: Add a log_name config option rather than just using the tag?

    # Expose attr_readers to make testing of metadata more direct than only
    # testing it indirectly through metadata sent with logs.
    attr_reader :running_on_managed_vm
    attr_reader :gae_backend_name
    attr_reader :gae_backend_version
    attr_reader :service_name
    attr_reader :common_labels

    def initialize
      super
      # use the global logger
      @log = $log # rubocop:disable Style/GlobalVars
    end

    def configure(conf)
      super

      unless @auth_method.nil?
        @log.warn 'auth_method is deprecated; please migrate to using ' \
          'Application Default Credentials.'
        if @auth_method == 'private_key'
          if !@private_key_email
            fail Fluent::ConfigError, '"private_key_email" must be ' \
              'specified if auth_method is "private_key"'
          elsif !@private_key_path
            fail Fluent::ConfigError, '"private_key_path" must be ' \
              'specified if auth_method is "private_key"'
          elsif !@private_key_passphrase
            fail Fluent::ConfigError, '"private_key_passphrase" must be ' \
              'specified if auth_method is "private_key"'
          end
        end
      end

      @compiled_kubernetes_tag_regexp = nil
      if @kubernetes_tag_regexp
        @compiled_kubernetes_tag_regexp = Regexp.new(@kubernetes_tag_regexp)
      end

      @cloudfunctions_tag_regexp =
        /\.(?<encoded_function_name>.+)\.\d+-[^-]+_default_worker$/
      @cloudfunctions_log_regexp = /^
        (?:\[(?<severity>.)\])?
        \[(?<timestamp>.{24})\]
        (?:\[(?<execution_id>[^\]]+)\])?
        [ ](?<text>.*)$/x

      # Detect the metadata.
      ext = detect_metadata(@use_metadata_service, @detect_subservice)
      unless @project_id
        # If no project_id is set, we can attempt to extract the project_id
        # from the credentials.
        begin
          get_credentials(LOGGING_SCOPE)
          @project_id = project_id_from_credentials
        rescue StandardError => _ # rubocop:disable Lint/HandleExceptions
          # Ignore errors trying to read project_id from credentials.
        end
      end

      # all metadata parameters must now be set
      unless @project_id && @zone && @vm_id
        missing = []
        missing << 'project_id' unless @project_id
        missing << 'zone' unless @zone
        missing << 'vm_id' unless @vm_id
        fail Fluent::ConfigError, 'Unable to obtain metadata parameters: ' +
          missing.join(' ')
      end

      # Translate metadata into labels.
      # TODO: Send instance tags as labels as well?
      @common_labels = {}
      case @platform
      when Fluent::GoogleUtil::Platform::EC2
        @common_labels["#{EC2_SERVICE}/resource_type"] = 'instance'
        @common_labels["#{EC2_SERVICE}/resource_id"] = @vm_id
        @common_labels["#{EC2_SERVICE}/resource_name"] = @vm_name
        @common_labels["#{EC2_SERVICE}/account_id"] = ext.ec2_account_id \
          unless ext.nil?
      else
        @common_labels["#{COMPUTE_SERVICE}/resource_type"] = 'instance'
        @common_labels["#{COMPUTE_SERVICE}/resource_id"] = @vm_id
        @common_labels["#{COMPUTE_SERVICE}/resource_name"] = @vm_name
      end

      # Default this to false; it is only overwritten if we detect Managed VM.
      @running_on_managed_vm = false

      # Default this to false; it is only overwritten if we detect Cloud
      # Functions.
      @running_cloudfunctions = false

      case @service_name
      when DATAFLOW_SERVICE
        @dataflow_job_id = ext.dataflow_job_id
        common_labels["#{DATAFLOW_SERVICE}/job_id"] = @dataflow_job_id
      when APPENGINE_SERVICE
        @running_on_managed_vm = true
        unless ext.nil?
          @gae_backend_name = ext.gae_backend_name
          @gae_backend_version = ext.gae_backend_version
          common_labels["#{APPENGINE_SERVICE}/module_id"] = @gae_backend_name
          common_labels["#{APPENGINE_SERVICE}/version_id"] = \
            @gae_backend_version
        end
      when CONTAINER_SERVICE
        common_labels["#{CONTAINER_SERVICE}/instance_id"] = @vm_id
        common_labels["#{CONTAINER_SERVICE}/cluster_name"] = \
          ext.kube_cluster_name unless ext.nil?
      when CLOUDFUNCTIONS_SERVICE
        @running_cloudfunctions = true
        common_labels["#{CONTAINER_SERVICE}/instance_id"] = @vm_id
        unless ext.nil?
          @gcf_region = ext.gcf_region
          common_labels["#{CONTAINER_SERVICE}/cluster_name"] = \
            ext.kube_cluster_name
        end
      end

      # Log an informational message containing the Logs viewer URL
      @log.info 'Logs viewer address: ',
                'https://console.developers.google.com/project/', @project_id,
                '/logs?service=', @service_name, '&key1=instance&key2=', @vm_id
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

    def format(tag, time, record)
      [tag, time, record].to_msgpack
    end

    def write(chunk)
      # Group the entries since we have to make one call per tag.
      grouped_entries = {}
      chunk.msgpack_each do |tag, *arr|
        grouped_entries[tag] = [] unless grouped_entries.key?(tag)
        grouped_entries[tag].push(arr)
      end

      grouped_entries.each do |tag, arr|
        entries = []
        labels = @common_labels.clone

        if @running_cloudfunctions
          # If the current group of entries is coming from a Cloud Functions
          # function, the function name can be extracted from the tag.
          match_data = @cloudfunctions_tag_regexp.match(tag)
          if match_data
            # Service name is set to Cloud Functions only for logs actually
            # coming from a function.
            @service_name = CLOUDFUNCTIONS_SERVICE
            labels["#{CLOUDFUNCTIONS_SERVICE}/region"] = @gcf_region
            labels["#{CLOUDFUNCTIONS_SERVICE}/function_name"] =
              decode_cloudfunctions_function_name(
                match_data['encoded_function_name'])
          else
            # Other logs are considered as coming from the Container Engine
            # service.
            @service_name = CONTAINER_SERVICE
          end
        end
        if @service_name == CONTAINER_SERVICE && @compiled_kubernetes_tag_regexp
          # Container logs in Kubernetes are tagged based on where they came
          # from, so we can extract useful metadata from the tag.
          # Do this here to avoid having to repeat it for each record.
          match_data = @compiled_kubernetes_tag_regexp.match(tag)
          if match_data
            %w(namespace_name pod_name container_name).each do |field|
              labels["#{CONTAINER_SERVICE}/#{field}"] = match_data[field]
            end
          end
        end
        is_container_json = nil
        arr.each do |time, record|
          next unless record.is_a?(Hash)

          entry = Google::Apis::LoggingV1beta3::LogEntry.new(
            metadata: Google::Apis::LoggingV1beta3::LogEntryMetadata.new(
              service_name: @service_name,
              project_id: @project_id,
              zone: @zone,
              labels: {}
            ))

          if @service_name == CLOUDFUNCTIONS_SERVICE && record.key?('log')
            @cloudfunctions_log_match =
              @cloudfunctions_log_regexp.match(record['log'])
          end
          if @service_name == CONTAINER_SERVICE
            # Move the stdout/stderr annotation from the record into a label
            field_to_label(record, 'stream', entry.metadata.labels,
                           "#{CONTAINER_SERVICE}/stream")
            # If the record has been annotated by the kubernetes_metadata_filter
            # plugin, then use that metadata. Otherwise, rely on commonLabels
            # populated at the grouped_entries level from the group's tag.
            if record.key?('kubernetes')
              handle_container_metadata(record, entry)
            end
            # If the log from the user container is json, we want to export it
            # as a structured log. Now that we've pulled out all the
            # container-specific metadata from the record, we can replace the
            # record with the json that the user logged.
            # To save CPU in the common case of unstructured logs, only check if
            # the contents are parsable as json for the first entry of each
            # batch.
            if is_container_json.nil? && record.key?('log')
              record_json = parse_json_or_nil(record['log'])
              if record_json.nil?
                is_container_json = false
              else
                record = record_json
                is_container_json = true
              end
            elsif is_container_json && record.key?('log')
              record_json = parse_json_or_nil(record['log'])
              record = record_json unless record_json.nil?
            end
          end

          set_timestamp(record, entry, time)
          set_severity(record, entry)
          set_http_request(record, entry)

          # If a field is present in the label_map, send its value as a label
          # (mapping the field name to label name as specified in the config)
          # and do not send that field as part of the payload.
          if @label_map
            @label_map.each do |field, label|
              field_to_label(record, field, entry.metadata.labels, label)
            end
          end

          if @service_name == CLOUDFUNCTIONS_SERVICE &&
             @cloudfunctions_log_match &&
             @cloudfunctions_log_match['execution_id']
            entry.metadata.labels['execution_id'] =
              @cloudfunctions_log_match['execution_id']
          end

          set_payload(record, entry, is_container_json)
          entry.metadata.labels = nil if entry.metadata.labels.empty?

          entries.push(entry)
        end
        # Don't send an empty request if we rejected all the entries.
        next if entries.empty?

        log_name = log_name(tag, labels)

        begin
          # Does the actual write to the cloud logging api.
          # The URI of the write is constructed by the Google::Api request;
          # it is equivalent to this URL:
          # 'https://logging.googleapis.com/v1beta3/projects/' \
          #   "#{@project_id}/logs/#{log_name}/entries:write"

          client = api_client

          write_request = \
            Google::Apis::LoggingV1beta3::WriteLogEntriesRequest.new(
              common_labels: labels,
              entries: entries)

          # TODO: RequestOptions
          client.write_log_entries(@project_id, log_name, write_request)

          # Let the user explicitly know when the first call succeeded,
          # to aid with verification and troubleshooting.
          unless @successful_call
            @successful_call = true
            @log.info 'Successfully sent to Google Cloud Logging API.'
          end

        rescue Google::Apis::ServerError => error
          # Server error, so retry via re-raising the error.
          raise error

        rescue Google::Apis::AuthorizationError => error
          # Authorization error.
          # These are usually solved via a `gcloud auth` call, or by modifying
          # the permissions on the Google Cloud project.
          dropped = entries.length
          @log.warn "Dropping #{dropped} log message(s)",
                    error_class: error.class.to_s, error: error.to_s

        rescue Google::Apis::ClientError => error
          # Most ClientErrors indicate a problem with the request itself and
          # should not be retried.
          dropped = entries.length
          @log.warn "Dropping #{dropped} log message(s)",
                    error_class: error.class.to_s, error: error.to_s
        end
      end
    end

    private

    def parse_json_or_nil(input)
      # Only here to please rubocop...
      return nil if input.nil?

      begin
        return JSON.parse(input)
      rescue JSON::ParserError
        return nil
      end
    end

    def set_timestamp(record, entry, time)
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
      elsif @service_name == CLOUDFUNCTIONS_SERVICE &&
            @cloudfunctions_log_match
        timestamp = DateTime.parse(@cloudfunctions_log_match['timestamp'])
        ts_secs = timestamp.strftime('%s')
        ts_nanos = timestamp.strftime('%N')
      else
        timestamp = Time.at(time)
        ts_secs = timestamp.tv_sec
        ts_nanos = timestamp.tv_nsec
      end
      entry.metadata.timestamp = {
        seconds: ts_secs,
        nanos: ts_nanos
      }
    end

    def set_severity(record, entry)
      if @service_name == CLOUDFUNCTIONS_SERVICE
        if @cloudfunctions_log_match && @cloudfunctions_log_match['severity']
          entry.metadata.severity =
            parse_severity(@cloudfunctions_log_match['severity'])
        elsif record.key?('stream') && record['stream'] == 'stdout'
          entry.metadata.severity = 'INFO'
          record.delete('stream')
        elsif record.key?('stream') && record['stream'] == 'stderr'
          entry.metadata.severity = 'ERROR'
          record.delete('stream')
        else
          entry.metadata.severity = 'DEFAULT'
        end
      elsif record.key?('severity')
        entry.metadata.severity = parse_severity(record['severity'])
        record.delete('severity')
      else
        entry.metadata.severity = 'DEFAULT'
      end
    end

    def set_http_request(record, entry)
      return nil unless record['httpRequest'].is_a?(Hash)
      input = record['httpRequest']
      output = Google::Apis::LoggingV1beta3::HttpRequest.new
      output.request_method = input.delete('requestMethod')
      output.request_url = input.delete('requestUrl')
      output.request_size = input.delete('requestSize')
      output.status = input.delete('status')
      output.response_size = input.delete('responseSize')
      output.user_agent = input.delete('userAgent')
      output.remote_ip = input.delete('remoteIp')
      output.referer = input.delete('referer')
      output.cache_hit = input.delete('cacheHit')
      output.validated_with_origin_server = \
        input.delete('validatedWithOriginServer')
      record.delete('httpRequest') if input.empty?
      entry.http_request = output
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

    def decode_cloudfunctions_function_name(function_name)
      function_name.gsub(/c\.[a-z]/) { |s| s.upcase[-1] }
        .gsub('u.u', '_').gsub('d.d', '$').gsub('a.a', '@').gsub('p.p', '.')
    end

    # Requires that record has a 'kubernetes' field.
    def handle_container_metadata(record, entry)
      fields = %w(namespace_id namespace_name pod_id pod_name container_name)
      fields.each do |field|
        field_to_label(record['kubernetes'], field, entry.metadata.labels,
                       "#{CONTAINER_SERVICE}/#{field}")
      end
      # Prepend label/ to all user-defined labels' keys.
      if record['kubernetes'].key?('labels')
        record['kubernetes']['labels'].each do |key, value|
          entry.metadata.labels["label/#{key}"] = value
        end
      end
      # We've explicitly consumed all the fields we care about -- don't litter
      # the log entries with the remaining fields that the kubernetes metadata
      # filter plugin includes (or an empty 'kubernetes' field).
      record.delete('kubernetes')
      record.delete('docker')
    end

    def field_to_label(record, field, labels, label)
      return unless record.key?(field)
      labels[label] = record[field].to_s
      record.delete(field)
    end

    def set_payload(record, entry, is_container_json)
      # Use textPayload if
      # 1. This is a Cloud Functions log that matched the expected regexp
      # 2. This is a Cloud Functions log and the 'log' key is available
      # 3. This is an unstructured Container log and the 'log' key is available
      # 4. The only remaining key is 'message'
      if @service_name == CLOUDFUNCTIONS_SERVICE && @cloudfunctions_log_match
        entry.text_payload = @cloudfunctions_log_match['text']
      elsif @service_name == CLOUDFUNCTIONS_SERVICE && record.key?('log')
        entry.text_payload = record['log']
      elsif @service_name == CONTAINER_SERVICE && record.key?('log') &&
            !is_container_json
        entry.text_payload = record['log']
      elsif record.size == 1 && record.key?('message')
        entry.text_payload = record['message']
      else
        entry.struct_payload = record
      end
    end

    def log_name(tag, commonLabels)
      if @service_name == CLOUDFUNCTIONS_SERVICE
        return 'cloud-functions'
      elsif @running_on_managed_vm
        # Add a prefix to Managed VM logs to prevent namespace collisions.
        return "#{APPENGINE_SERVICE}/#{tag}"
      elsif @service_name == CONTAINER_SERVICE
        # For Kubernetes logs, use just the container name as the log name
        # if we have it.
        container_name_key = "#{CONTAINER_SERVICE}/container_name"
        if commonLabels && commonLabels.key?(container_name_key)
          return commonLabels[container_name_key]
        end
      end
      tag
    end

    def init_api_client
      # TODO: Use a non-default ClientOptions object.
      Google::Apis::ClientOptions.default.application_name = PLUGIN_NAME
      Google::Apis::ClientOptions.default.application_version = PLUGIN_VERSION
      @client = Google::Apis::LoggingV1beta3::LoggingService.new
      @client.authorization = get_credentials(LOGGING_SCOPE)
    end

    def api_client
      authorize
      @client
    end
  end
end
