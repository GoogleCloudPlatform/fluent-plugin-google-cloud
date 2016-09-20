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
require 'open-uri'
require 'socket'
require 'time'
require 'yaml'
require 'google/apis'
require 'google/apis/logging_v2beta1'
require 'googleauth'

module Fluent
  # fluentd output plugin for the Stackdriver Logging API
  class GoogleCloudOutput < BufferedOutput
    Fluent::Plugin.register_output('google_cloud', self)

    PLUGIN_NAME = 'Fluentd Google Cloud Logging plugin'
    PLUGIN_VERSION = '0.5.2'

    # Constants for service names.
    APPENGINE_SERVICE = 'appengine.googleapis.com'
    CLOUDFUNCTIONS_SERVICE = 'cloudfunctions.googleapis.com'
    COMPUTE_SERVICE = 'compute.googleapis.com'
    CONTAINER_SERVICE = 'container.googleapis.com'
    DATAFLOW_SERVICE = 'dataflow.googleapis.com'
    EC2_SERVICE = 'ec2.amazonaws.com'
    ML_SERVICE = 'ml.googleapis.com'

    APPENGINE_RESOURCE_TYPE = 'gae_app'
    CLOUDFUNCTIONS_RESOURCE_TYPE = 'cloud_function'
    COMPUTE_RESOURCE_TYPE = 'gce_instance'
    CONTAINER_RESOURCE_TYPE = 'container'
    DATAFLOW_RESOURCE_TYPE = 'dataflow_step'
    EC2_RESOURCE_TYPE = 'aws_ec2_instance'
    ML_RESOURCE_TYPE = 'ml_job'

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
    attr_reader :project_id
    attr_reader :zone
    attr_reader :vm_id
    attr_reader :running_on_managed_vm
    attr_reader :gae_backend_name
    attr_reader :gae_backend_version
    attr_reader :resource
    attr_reader :common_labels

    def initialize
      super
      # use the global logger
      @log = $log # rubocop:disable Style/GlobalVars
    end

    def configure(conf)
      super

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

      # TODO: Send instance tags as labels as well?
      @common_labels = {}
      @common_labels.merge!(@labels) if @labels
      @resource = Google::Apis::LoggingV2beta1::MonitoredResource.new(
        labels: {})

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

      # set attributes from metadata (unless overriden by static config)
      @vm_name = Socket.gethostname if @vm_name.nil?
      @platform = detect_platform
      case @platform
      when Platform::GCE
        if @project_id.nil?
          @project_id = fetch_gce_metadata('project/project-id')
        end
        if @zone.nil?
          # this returns "projects/<number>/zones/<zone>"; we only want
          # the part after the final slash.
          fully_qualified_zone = fetch_gce_metadata('instance/zone')
          @zone = fully_qualified_zone.rpartition('/')[2]
        end
        @vm_id = fetch_gce_metadata('instance/id') if @vm_id.nil?
      when Platform::EC2
        metadata = fetch_ec2_metadata
        if @zone.nil? && metadata.key?('availabilityZone')
          @zone = 'aws:' + metadata['availabilityZone']
        end
        if @vm_id.nil? && metadata.key?('instanceId')
          @vm_id = metadata['instanceId']
        end
        if metadata.key?('accountId')
          resource.labels['aws_account'] = metadata['accountId']
        end
      when Platform::OTHER
        # do nothing
      else
        fail Fluent::ConfigError, 'Unknown platform ' + @platform
      end

      # If we still don't have a project ID, try to obtain it from the
      # credentials.
      if @project_id.nil?
        @project_id = CredentialsInfo.project_id
        @log.info 'Set Project ID from credentials: ', @project_id unless
          @project_id.nil?
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

      # Default this to false; it is only overwritten if we detect Managed VM.
      @running_on_managed_vm = false

      # Default this to false; it is only overwritten if we detect Cloud
      # Functions.
      @running_cloudfunctions = false

      # Set up the MonitoredResource, labels, etc. based on the config
      case @platform
      when Platform::GCE
        logviewer_service_name = COMPUTE_SERVICE
        @resource.type = COMPUTE_RESOURCE_TYPE
        # TODO: introduce a new MonitoredResource-centric configuration and
        # deprecate subservice-name; for now, translate known uses.
        if @subservice_name
          logviewer_service_name = @subservice_name
          # TODO: what should we do if we encounter an unknown value?
          if @subservice_name == DATAFLOW_SERVICE
            @resource.type = DATAFLOW_RESOURCE_TYPE
          elsif @subservice_name == ML_SERVICE
            @resource.type = ML_RESOURCE_TYPE
          end
        elsif @detect_subservice
          # Check for specialized GCE environments.
          # TODO: Add config options for these to allow for running outside GCE?
          attributes = fetch_gce_metadata('instance/attributes/').split
          # Do nothing, just don't populate other service's labels.
          if attributes.include?('gae_backend_name') &&
             attributes.include?('gae_backend_version')
            # Managed VM
            @running_on_managed_vm = true
            @gae_backend_name =
                fetch_gce_metadata('instance/attributes/gae_backend_name')
            @gae_backend_version =
                fetch_gce_metadata('instance/attributes/gae_backend_version')
            logviewer_service_name = APPENGINE_SERVICE
            @resource.type = APPENGINE_RESOURCE_TYPE
            @resource.labels['module_id'] = @gae_backend_name
            @resource.labels['version_id'] = @gae_backend_version
          elsif attributes.include?('kube-env')
            # Kubernetes/Container Engine
            logviewer_service_name = CONTAINER_SERVICE
            @resource.type = CONTAINER_RESOURCE_TYPE
            @raw_kube_env = fetch_gce_metadata('instance/attributes/kube-env')
            @kube_env = YAML.load(@raw_kube_env)
            @resource.labels['cluster_name'] =
              cluster_name_from_kube_env(@kube_env)
            detect_cloudfunctions(attributes)
          end
        end
        # Some services have the GCE instance_id and zone as MonitoredResource
        # labels; for other services we send them as entry labels.
        if @resource.type == COMPUTE_RESOURCE_TYPE ||
           @resource.type == CONTAINER_RESOURCE_TYPE
          @resource.labels['instance_id'] = @vm_id
          @resource.labels['zone'] = @zone
        else
          common_labels["#{COMPUTE_SERVICE}/resource_id"] = @vm_id
          common_labels["#{COMPUTE_SERVICE}/zone"] = @zone
        end
        common_labels["#{COMPUTE_SERVICE}/resource_name"] = @vm_name
      when Platform::EC2
        logviewer_service_name = EC2_SERVICE
        @resource.type = EC2_RESOURCE_TYPE
        @resource.labels['instance_id'] = @vm_id
        @resource.labels['region'] = @zone
        # the aws_account label is populated above.
        common_labels["#{EC2_SERVICE}/resource_name"] = @vm_name
      when Platform::OTHER
        # Use GCE as the default environment.
        logviewer_service_name = COMPUTE_SERVICE
        @resource.type = COMPUTE_RESOURCE_TYPE
        @resource.labels['instance_id'] = @vm_id
        @resource.labels['zone'] = @zone
        common_labels["#{COMPUTE_SERVICE}/resource_name"] = @vm_name
      end
      resource_labels = extract_resource_labels(@resource.type, common_labels)
      @resource.labels.merge!(resource_labels) unless
        resource_labels.nil? || resource_labels.empty?

      # The resource and labels are now set up; ensure they can't be modified
      # without first duping them.
      @resource.freeze
      @resource.labels.freeze
      @common_labels.freeze

      # Log an informational message containing the Logs viewer URL
      # TODO: once the log viewer supports v2 services, use resource.type and
      # remove all references to logviewer_service_name above.
      @log.info 'Logs viewer address: ',
                'https://console.developers.google.com/project/', @project_id,
                '/logs?service=', logviewer_service_name,
                '&key1=instance&key2=', @vm_id
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
        resource = @resource
        entries = []
        # Note that we assume that labels added to common_labels below are not
        # 'service' labels (i.e. we do not call extract_resource_labels again).
        common_labels = @common_labels

        if @running_cloudfunctions
          # If the current group of entries is coming from a Cloud Functions
          # function, the function name can be extracted from the tag.
          match_data = @cloudfunctions_tag_regexp.match(tag)
          if match_data
            # Resource type is set to Cloud Functions only for logs actually
            # coming from a function, otherwise we leave it as Container.
            resource = resource.dup
            resource.type = CLOUDFUNCTIONS_RESOURCE_TYPE
            resource.labels['region'] = @gcf_region
            resource.labels['function_name'] =
              decode_cloudfunctions_function_name(
                match_data['encoded_function_name'])
            # Move GKE container labels from the MonitoredResource to the
            # LogEntry.
            instance_id = resource.labels.delete('instance_id')
            common_labels = common_labels.dup
            common_labels["#{CONTAINER_SERVICE}/cluster_name"] =
              resource.labels.delete('cluster_name')
            common_labels["#{CONTAINER_SERVICE}/instance_id"] = instance_id
            common_labels["#{COMPUTE_SERVICE}/resource_id"] = instance_id
            common_labels["#{COMPUTE_SERVICE}/zone"] =
              resource.labels.delete('zone')
          end
        end
        if resource.type == CONTAINER_RESOURCE_TYPE &&
           @compiled_kubernetes_tag_regexp
          # Container logs in Kubernetes are tagged based on where they came
          # from, so we can extract useful metadata from the tag.
          # Do this here to avoid having to repeat it for each record.
          match_data = @compiled_kubernetes_tag_regexp.match(tag)
          if match_data
            resource = resource.dup
            resource.labels['container_name'] = match_data['container_name']
            common_labels = common_labels.dup
            %w(namespace_name pod_name).each do |field|
              common_labels["#{CONTAINER_SERVICE}/#{field}"] = match_data[field]
            end
          end
        end

        # freeze the per-request state.  Any further changes must be made
        # on a per-entry basis.
        resource.freeze
        resource.labels.freeze
        common_labels.freeze

        arr.each do |time, record|
          next unless record.is_a?(Hash)

          entry = Google::Apis::LoggingV2beta1::LogEntry.new(
            labels: {})

          if resource.type == CLOUDFUNCTIONS_RESOURCE_TYPE && record.key?('log')
            @cloudfunctions_log_match =
              @cloudfunctions_log_regexp.match(record['log'])
          end
          if resource.type == CONTAINER_RESOURCE_TYPE
            # Move the stdout/stderr annotation from the record into a label
            field_to_label(record, 'stream', entry.labels,
                           "#{CONTAINER_SERVICE}/stream")
            # If the record has been annotated by the kubernetes_metadata_filter
            # plugin, then use that metadata. Otherwise, rely on commonLabels
            # populated at the grouped_entries level from the group's tag.
            if record.key?('kubernetes')
              entry.resource = resource.dup
              resource = entry.resource
              handle_container_metadata(record, entry)
            end

            # Save the timestamp if available, then clear it out to allow for
            # determining whether we should parse the log or message field.
            timestamp = record.key?('time') ? record['time'] : nil
            record.delete('time')
            # If the log is json, we want to export it as a structured log
            # unless there is additional metadata that would be lost.
            is_json = false
            if record.length == 1 && record.key?('log')
              record_json = parse_json_or_nil(record['log'])
            end
            if record.length == 1 && record.key?('message')
              record_json = parse_json_or_nil(record['message'])
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

          set_timestamp(resource, record, entry, time)
          set_severity(resource, record, entry)
          set_http_request(record, entry)

          # If a field is present in the label_map, send its value as a label
          # (mapping the field name to label name as specified in the config)
          # and do not send that field as part of the payload.
          if @label_map
            @label_map.each do |field, label|
              field_to_label(record, field, entry.labels, label)
            end
          end

          if resource.type == CLOUDFUNCTIONS_RESOURCE_TYPE &&
             @cloudfunctions_log_match &&
             @cloudfunctions_log_match['execution_id']
            entry.labels['execution_id'] =
              @cloudfunctions_log_match['execution_id']
          end

          set_payload(resource, record, entry, is_json)
          resource_labels = extract_resource_labels(resource.type, entry.labels)
          if !resource_labels.nil? && !resource_labels.empty?
            entry.resource = resource.dup
            entry.resource.labels.merge!(resource_labels)
          end
          entry.labels = nil if entry.labels.empty?
          entries.push(entry)
        end
        # Don't send an empty request if we rejected all the entries.
        next if entries.empty?

        begin
          # Does the actual write to the cloud logging api.
          client = api_client
          log_name = "projects/#{@project_id}/logs/#{log_name(tag, resource)}"
          write_request = \
            Google::Apis::LoggingV2beta1::WriteLogEntriesRequest.new(
              log_name: log_name,
              resource: resource,
              labels: common_labels,
              entries: entries)

          # TODO: RequestOptions
          client.write_entry_log_entries(write_request)

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
        @log.debug 'Failed to access metadata service: ', error: e
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

    def fetch_ec2_metadata
      fail "Called fetch_ec2_metadata with platform=#{@platform}" unless
        @platform == Platform::EC2
      # See http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
      open('http://' + METADATA_SERVICE_ADDR +
           '/latest/dynamic/instance-identity/document') do |f|
        contents = f.read
        return JSON.parse(contents)
      end
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

    def detect_cloudfunctions(attributes)
      return unless attributes.include?('gcf_region')
      # Cloud Functions detected
      @running_cloudfunctions = true
      @gcf_region = fetch_gce_metadata('instance/attributes/gcf_region')
    end

    def cluster_name_from_kube_env(kube_env)
      return kube_env['CLUSTER_NAME'] if kube_env.key?('CLUSTER_NAME')
      instance_prefix = kube_env['INSTANCE_PREFIX']
      gke_name_match = /^gke-(.+)-[0-9a-f]{8}$/.match(instance_prefix)
      return gke_name_match.captures[0] if gke_name_match &&
                                           !gke_name_match.captures.empty?
      instance_prefix
    end

    def set_timestamp(resource, record, entry, time)
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
      elsif resource.type == CLOUDFUNCTIONS_RESOURCE_TYPE &&
            @cloudfunctions_log_match
        timestamp = DateTime.parse(@cloudfunctions_log_match['timestamp'])
        ts_secs = timestamp.strftime('%s')
        ts_nanos = timestamp.strftime('%N')
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
      entry.timestamp = {
        seconds: ts_secs,
        nanos: ts_nanos
      }
    end

    def set_severity(resource, record, entry)
      if resource.type == CLOUDFUNCTIONS_RESOURCE_TYPE
        if @cloudfunctions_log_match && @cloudfunctions_log_match['severity']
          entry.severity = parse_severity(@cloudfunctions_log_match['severity'])
        elsif record.key?('stream') && record['stream'] == 'stdout'
          entry.severity = 'INFO'
          record.delete('stream')
        elsif record.key?('stream') && record['stream'] == 'stderr'
          entry.severity = 'ERROR'
          record.delete('stream')
        else
          entry.severity = 'DEFAULT'
        end
      elsif record.key?('severity')
        entry.severity = parse_severity(record['severity'])
        record.delete('severity')
      elsif resource.type == CONTAINER_RESOURCE_TYPE &&
            entry.labels.key?("#{CONTAINER_SERVICE}/stream")
        stream = entry.labels["#{CONTAINER_SERVICE}/stream"]
        if stream == 'stdout'
          entry.severity = 'INFO'
        elsif stream == 'stderr'
          entry.severity = 'ERROR'
        else
          entry.severity = 'DEFAULT'
        end
      else
        entry.severity = 'DEFAULT'
      end
    end

    def set_http_request(record, entry)
      return nil unless record['httpRequest'].is_a?(Hash)
      input = record['httpRequest']
      output = Google::Apis::LoggingV2beta1::HttpRequest.new
      output.request_method = input.delete('requestMethod')
      output.request_url = input.delete('requestUrl')
      output.request_size = input.delete('requestSize')
      output.status = input.delete('status')
      output.response_size = input.delete('responseSize')
      output.user_agent = input.delete('userAgent')
      output.remote_ip = input.delete('remoteIp')
      output.referer = input.delete('referer')
      output.cache_hit = input.delete('cacheHit')
      output.cache_validated_with_origin_server = \
        input.delete('cacheValidatedWithOriginServer')
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

    def decode_cloudfunctions_function_name(function_name)
      function_name.gsub(/c\.[a-z]/) { |s| s.upcase[-1] }
        .gsub('u.u', '_').gsub('d.d', '$').gsub('a.a', '@').gsub('p.p', '.')
    end

    # Requires that record has a 'kubernetes' field.
    def handle_container_metadata(record, entry)
      %w(namespace_id pod_id container_name).each do |field|
        field_to_label(record['kubernetes'], field, entry.resource.labels,
                       field)
      end
      %w(namespace_name pod_name).each do |field|
        field_to_label(record['kubernetes'], field, entry.labels,
                       "#{CONTAINER_SERVICE}/#{field}")
      end
      # Prepend label/ to all user-defined labels' keys.
      if record['kubernetes'].key?('labels')
        record['kubernetes']['labels'].each do |key, value|
          entry.labels["label/#{key}"] = value
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

    def set_payload(resource, record, entry, is_json)
      # If this is a Cloud Functions log that matched the expected regexp,
      # use text payload. Otherwise, use JSON if we found valid JSON, or text
      # payload in the following cases:
      # 1. This is a Cloud Functions log and the 'log' key is available
      # 2. This is an unstructured Container log and the 'log' key is available
      # 3. The only remaining key is 'message'
      if resource.type == CLOUDFUNCTIONS_RESOURCE_TYPE &&
         @cloudfunctions_log_match
        entry.text_payload = @cloudfunctions_log_match['text']
      elsif resource.type == CLOUDFUNCTIONS_RESOURCE_TYPE && record.key?('log')
        entry.text_payload = record['log']
      elsif is_json
        entry.json_payload = record
      elsif resource.type == CONTAINER_RESOURCE_TYPE && record.key?('log')
        entry.text_payload = record['log']
      elsif record.size == 1 && record.key?('message')
        entry.text_payload = record['message']
      else
        entry.json_payload = record
      end
    end

    def log_name(tag, resource)
      if resource.type == CLOUDFUNCTIONS_RESOURCE_TYPE
        return 'cloud-functions'
      elsif @running_on_managed_vm
        # Add a prefix to Managed VM logs to prevent namespace collisions.
        return "#{APPENGINE_SERVICE}%2F#{tag}"
      elsif resource.type == CONTAINER_RESOURCE_TYPE
        # For Kubernetes logs, use just the container name as the log name
        # if we have it.
        if resource.labels && resource.labels.key?('container_name')
          return resource.labels['container_name']
        end
      end
      tag
    end

    # Some services set labels (via configuring 'labels' or 'label_map') which
    # are now MonitoredResource labels in v2.
    # For these services, remove resource labels from 'labels' and return a
    # Hash of labels to be merged into the MonitoredResource labels.
    # Otherwise, return nil and leave 'labels' unmodified.
    def extract_resource_labels(resource_type, labels)
      if resource_type == DATAFLOW_RESOURCE_TYPE
        label_prefix = DATAFLOW_SERVICE
        labels_to_extract = %w(region job_name job_id step_id)
      elsif resource_type == ML_RESOURCE_TYPE
        label_prefix = ML_SERVICE
        labels_to_extract = %w(job_id task_name)
      else
        return nil
      end

      resource_labels = {}
      labels_to_extract.each do |label|
        value = labels.delete("#{label_prefix}/#{label}")
        next unless value
        resource_labels[label] = value
      end
      resource_labels
    end

    def init_api_client
      # TODO: Use a non-default ClientOptions object.
      Google::Apis::ClientOptions.default.application_name = PLUGIN_NAME
      Google::Apis::ClientOptions.default.application_version = PLUGIN_VERSION
      @client = Google::Apis::LoggingV2beta1::LoggingService.new
      @client.authorization = Google::Auth.get_application_default(
        LOGGING_SCOPE)
    end

    def api_client
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
      @client
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
