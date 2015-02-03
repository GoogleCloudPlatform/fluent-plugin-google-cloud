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

module Fluent
  class GoogleCloudOutput < BufferedOutput
    Fluent::Plugin.register_output('google_cloud', self)

    # Constants for Google service names.
    APPENGINE_SERVICE = 'appengine.googleapis.com'
    COMPUTE_SERVICE = 'compute.googleapis.com'
    DATAFLOW_SERVICE = 'dataflow.googleapis.com'

    # Legal values:
    # 'compute_engine_service_account' - Use the service account automatically
    #   available on Google Compute Engine VMs. Note that this requires that
    #   the logs.writeonly API scope is enabled on the VM, and scopes can
    #   only be enabled at the time that a VM is created.
    # 'private_key' - Use the service account credentials (email, private key
    #   local file path, and file passphrase) provided below.
    config_param :auth_method, :string,
        :default => 'compute_engine_service_account'

    # Parameters necessary to use the private_key auth_method.
    config_param :private_key_email, :string, :default => nil
    config_param :private_key_path, :string, :default => nil
    config_param :private_key_passphrase, :string, :default => 'notasecret'
    config_param :fetch_gce_metadata, :bool, :default => true
    config_param :project_id, :string, :default => nil
    config_param :zone, :string, :default => nil
    config_param :vm_id, :string, :default => nil

    # TODO: Add a log_name config option rather than just using the tag?

    # Expose attr_readers to make testing of metadata more direct than only
    # testing it indirectly through metadata sent with logs.
    attr_reader :project_id
    attr_reader :zone
    attr_reader :vm_id
    attr_reader :running_on_managed_vm
    attr_reader :gae_backend_name
    attr_reader :gae_backend_version
    attr_reader :service_name
    attr_reader :common_labels

    def initialize
      super
      require 'cgi'
      require 'google/api_client'
      require 'google/api_client/auth/compute_service_account'
      require 'open-uri'
    end

    def configure(conf)
      super

      case @auth_method
      when 'private_key'
        if !@private_key_email
          raise Fluent::ConfigError, ('"private_key_email" must be ' +
              'specified if auth_method is "private_key"')
        elsif !@private_key_path
          raise Fluent::ConfigError, ('"private_key_path" must be ' +
              'specified if auth_method is "private_key"')
        elsif !@private_key_passphrase
          raise Fluent::ConfigError, ('"private_key_passphrase" must be ' +
              'specified if auth_method is "private_key"')
        end
      when 'compute_engine_service_account'
        # pass
      else
        raise Fluent::ConfigError,
            ('Unrecognized "auth_method" parameter. Please specify either ' +
             '"compute_engine_service_account" or "private_key".')
      end

      unless @fetch_gce_metadata
        unless @project_id && @zone && @vm_id
          raise Fluent::ConfigError,
              ('Please specify "project_id", "zone" and "vm_id" if you set "fetch_gce_metadata" to false')
        end
      end
    end

    def start
      super

      init_api_client()

      @successful_call = false

      if @fetch_gce_metadata
        # Grab metadata about the Google Compute Engine instance that we're on.
        @project_id = fetch_metadata('project/project-id')
        fully_qualified_zone = fetch_metadata('instance/zone')
        @zone = fully_qualified_zone.rpartition('/')[2]
        @vm_id = fetch_metadata('instance/id')
      end
      # TODO: Send instance tags and/or hostname with the logs as well?
      @common_labels = {}

      # If this is running on a Managed VM, grab the relevant App Engine
      # metadata as well.
      # TODO: Add config options for these to allow for running outside GCE?
      attributes_string = fetch_metadata('instance/attributes/')
      attributes = attributes_string.split
      if (attributes.include?('gae_backend_name') &&
          attributes.include?('gae_backend_version'))
        @running_on_managed_vm = true
        @gae_backend_name =
            fetch_metadata('instance/attributes/gae_backend_name')
        @gae_backend_version =
            fetch_metadata('instance/attributes/gae_backend_version')
        @service_name = APPENGINE_SERVICE
        common_labels["#{APPENGINE_SERVICE}/module_id"] = @gae_backend_name
        common_labels["#{APPENGINE_SERVICE}/version_id"] = @gae_backend_version
      elsif (attributes.include?('job_id'))
        @running_on_managed_vm = false
        @service_name = DATAFLOW_SERVICE
        @dataflow_job_id = fetch_metadata('instance/attributes/job_id')
        common_labels["#{DATAFLOW_SERVICE}/job_id"] = @dataflow_job_id
      else
        @running_on_managed_vm = false
        @service_name = COMPUTE_SERVICE
      end

      if (@service_name != DATAFLOW_SERVICE)
        common_labels["#{COMPUTE_SERVICE}/resource_type"] = 'instance'
        common_labels["#{COMPUTE_SERVICE}/resource_id"] = @vm_id
      end
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
        if !grouped_entries.has_key?(tag)
          grouped_entries[tag] = []
        end
        grouped_entries[tag].push(arr)
      end

      grouped_entries.each do |tag, arr|
        write_log_entries_request = {
          'commonLabels' => @common_labels,
          'entries' => [],
        }
        arr.each do |time, record|
          if (record.has_key?('timeNanos'))
            ts_secs = (record['timeNanos'] / 1000000000).to_i
            ts_nanos = record['timeNanos'] % 1000000000
            record.delete('timeNanos')
          else
            timestamp = Time.at(time)
            ts_secs = timestamp.tv_sec
            ts_nanos = timestamp.tv_nsec
          end
          entry = {
            'metadata' => {
              'serviceName' => @service_name,
              'projectId' => @project_id,
              'zone' => @zone,
              'timestamp' => {
                'seconds' => ts_secs,
                'nanos' => ts_nanos
              },
            },
          }
          if record.has_key?('severity')
            entry['metadata']['severity'] = parse_severity(record['severity'])
            record.delete('severity')
          else
            entry['metadata']['severity'] = 'DEFAULT'
          end

          # use textPayload if the only remainaing key is 'message',
          # otherwise use a struct.
          if (record.size == 1 && record.has_key?('message'))
            entry['textPayload'] = record['message']
          else
            entry['structPayload'] = record
          end
          write_log_entries_request['entries'].push(entry)
        end

        # Add a prefix to VMEngines logs to prevent namespace collisions,
        # and also escape the log name.
        log_name = CGI::escape(@running_on_managed_vm ?
                               "#{APPENGINE_SERVICE}/#{tag}" : tag)
        url = ('https://logging.googleapis.com/v1beta3/projects/' +
               "#{@project_id}/logs/#{log_name}/entries:write")
        begin
          client = api_client()
          request = client.generate_request({
            :uri => url,
            :body_object => write_log_entries_request,
            :http_method => 'POST',
            :authenticated => true
          })
          client.execute!(request)
          # Let the user explicitly know when the first call succeeded,
          # to aid with verification and troubleshooting.
          if (!@successful_call)
            @successful_call = true
            $log.info "Successfully sent to Google Cloud Logging API."
          end
        # Allow most exceptions to propagate, which will cause fluentd to
        # retry (with backoff), but in some cases we catch the error and
        # drop the request (we will emit a log message in those cases).
        rescue Google::APIClient::ClientError => error
          # Most ClientErrors indicate a problem with the request itself and
          # should not be retried, unless it is an authentication issue, in
          # which case we will retry the request via re-raising the exception.
          if (is_retriable_client_error(error))
            raise error
          end
          log_write_failure(write_log_entries_request, error)
        rescue JSON::GeneratorError => error
          # This happens if the request contains illegal characters;
          # do not retry it because it will fail repeatedly.
          log_write_failure(write_log_entries_request, error)
        end
      end
    end

    private

    RETRIABLE_CLIENT_ERRORS = Set.new [
      'Invalid Credentials',
      'Request had invalid credentials.',
      'The caller does not have permission',
      'Project has not enabled the API. Please use Google Developers Console to activate the API for your project.',
      'Unable to fetch access token (no scopes configured?)']

    def is_retriable_client_error(error)
      return RETRIABLE_CLIENT_ERRORS.include?(error.message)
    end

    def log_write_failure(request, error)
      dropped = request['entries'].length
      $log.warn "Dropping #{dropped} log message(s)",
        :error_class=>error.class.to_s, :error=>error.to_s
    end

    def fetch_metadata(metadata_path)
      open('http://metadata/computeMetadata/v1/' + metadata_path,
           {'Metadata-Flavor' => 'Google'}) do |f|
        f.read
      end
    end

    # Values permitted by the API for 'severity' (which is an enum).
    VALID_SEVERITIES = Set.new [
      'DEFAULT', 'DEBUG', 'INFO', 'NOTICE', 'WARNING', 'ERROR', 'CRITICAL',
      'ALERT', 'EMERGENCY']

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
    }

    def parse_severity(severity_str)
      # The API is case insensitive, but uppercase to make things simpler.
      severity = severity_str.upcase.strip

      # If the severity is already valid, just return it.
      if (VALID_SEVERITIES.include?(severity))
        return severity
      end

      # If the severity is an integer (string) return it as an integer,
      # truncated to the closest valid value (multiples of 100 between 0-800).
      if (/\A\d+\z/.match(severity))
        begin
          numeric_severity = (severity.to_i / 100) * 100
          if (numeric_severity < 0)
            return 0
          elsif (numeric_severity > 800)
            return 800
          else
            return numeric_severity
          end
        rescue
          return 'DEFAULT'
        end
      end

      # Try to translate the severity.
      if (SEVERITY_TRANSLATIONS.has_key?(severity))
        return SEVERITY_TRANSLATIONS[severity]
      end

      # If all else fails, use 'DEFAULT'.
      return 'DEFAULT'
    end

    def init_api_client
      @client = Google::APIClient.new(
        :application_name => 'Fluentd Google Cloud Logging plugin',
        :application_version => '0.2.2',
        :retries => 1)

      if @auth_method == 'private_key'
        key = Google::APIClient::PKCS12.load_key(@private_key_path,
                                                 @private_key_passphrase)
        jwt_asserter = Google::APIClient::JWTAsserter.new(
          @private_key_email, 'https://www.googleapis.com/auth/logging.write',
          key)
        @client.authorization = jwt_asserter.to_authorization
        @client.authorization.expiry = 3600  # 3600s is the max allowed value
      else
        @client.authorization = Google::APIClient::ComputeServiceAccount.new
      end
    end

    def api_client
      if !@client.authorization.expired?
        begin
          @client.authorization.fetch_access_token!
        rescue MultiJson::ParseError
          # Workaround an issue in the API client; just re-raise a more
          # descriptive error for the user (which will still cause a retry).
          raise Google::APIClient::ClientError,
            'Unable to fetch access token (no scopes configured?)'
        end
      end
      return @client
    end
  end
end
