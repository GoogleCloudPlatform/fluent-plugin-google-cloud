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
    end

    def start
      super

      init_api_client()

      # Grab metadata about the Google Compute Engine instance that we're on.
      @project_id = fetch_metadata('project/project-id')
      fully_qualified_zone = fetch_metadata('instance/zone')
      @zone = fully_qualified_zone.rpartition('/')[2]
      @vm_id = fetch_metadata('instance/id')
      # TODO: Send instance tags and/or hostname with the logs as well?
      @common_labels = []
      add_label(common_labels, "#{COMPUTE_SERVICE}/resource_type",
                'strValue', 'instance')
      add_label(common_labels, "#{COMPUTE_SERVICE}/resource_id",
                'strValue', @vm_id)

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
        add_label(common_labels, "#{APPENGINE_SERVICE}/module_id",
                  'strValue', @gae_backend_name)
        add_label(common_labels, "#{APPENGINE_SERVICE}/version_id",
                  'strValue', @gae_backend_version)
      else
        @running_on_managed_vm = false
        @service_name = COMPUTE_SERVICE
      end
    end

    def shutdown
      super
    end

    def format(tag, time, record)
      [tag, time, record].to_msgpack
    end

    def add_label(labels, key, type, value)
      labels.push({'key' => key, type => value})
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
          entry = {
            'metadata' => {
              'serviceName' => @service_name,
              'projectId' => @project_id,
              'zone' => @zone,
              'timeNanos' => (record['timeNanos'] or time * 1000000000)
            },
            'textPayload' => record['message']
            # TODO(salty): default severity?
          }
          if record.has_key?('severity')
            entry['metadata']['severity'] = record['severity']
          end
          if record.has_key?('thread')
            entry['metadata']['thread'] = record['thread']
          end
          write_log_entries_request['entries'].push(entry)
        end

        # TODO: (salty: unsure of the origin of this - investigate) Ignore the
        # extra info that can be automatically appended to the tag for certain
        # log types such as syslog.

        # Add a prefix to VMEngines logs to prevent namespace collisions,
        # and also escape the log name.
        log_name = CGI::escape(@running_on_managed_vm ?
                               "#{APPENGINE_SERVICE}/#{tag}" : tag)
        url = ('https://www.googleapis.com/logging/v1beta/projects/' +
               "#{@project_id}/logs/#{log_name}/entries:write")

        client = api_client()
        # TODO: Either handle errors locally or send all logs in a single
        # request. Otherwise if a single request raises an error, the buffering
        # plugin will retry the entire block, potentially leading to duplicates.
        # Adding sequence numbers could help with this as well.
        request = client.generate_request({
          :uri => url,
          :body_object => write_log_entries_request,
          :http_method => 'POST',
          :authenticated => true
        })
        client.execute!(request)
      end
    end

    private

    def fetch_metadata(metadata_path)
      open('http://metadata/computeMetadata/v1/' + metadata_path,
           {'Metadata-Flavor' => 'Google'}) do |f|
        f.read
      end
    end

    def init_api_client
      @client = Google::APIClient.new(
        :application_name => 'Fluentd Google Cloud Logging plugin',
        :application_version => '0.1.0')

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
        @client.authorization.fetch_access_token!
      end
      return @client
    end
  end
end
