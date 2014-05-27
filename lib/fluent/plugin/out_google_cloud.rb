module Fluent
  class GoogleCloudOutput < BufferedOutput
    Fluent::Plugin.register_output('google_cloud', self)

    def initialize
      super
      require 'google/api_client'
      require 'google/api_client/auth/compute_service_account'
      require 'rest_client'
    end

    def configure(conf)
      super
    end

    def start
      super

      @client = nil
      # TODO: Switch over to using api client when the logs API is discoverable.
      #@api = api_client().discovered_api('logs', 'v1')
      puts api_client()

      # Grab metadata about the Google Compute Engine instance that we're on.
      @project_id = fetch_metadata('project/numeric-project-id')
      fully_qualified_zone = fetch_metadata('instance/zone')
      @zone = fully_qualified_zone.rpartition('/')[2]
      @vm_id = fetch_metadata('instance/id')
      # TODO: Send instance tags and/or hostname with the logs as well?

      # If this is running on a Managed VM, grab the relevant App Engine
      # metadata as well.
      # TODO: Use a configuration flag instead of detecting automatically?
      attributes_string = fetch_metadata('instance/attributes/')
      attributes = attributes_string.split
      if attributes.include?('gae_backend_name') &&
         attributes.include?('gae_backend_version')
        @running_on_managed_vm = true
        @gae_backend_name =
          fetch_metadata('instance/attributes/gae_backend_name')
        @gae_backend_version =
          fetch_metadata('instance/attributes/gae_backend_version')
      else
        @running_on_managed_vm = false
      end
    end

    def shutdown
      super
    end

    def format(tag, time, record)
      [tag, time, record['message']].to_msgpack
    end

    def write(chunk)
      payload = {
        'metadata' => {
          'project' => @project_id,
          'location' => @zone
        }
      }
      if @running_on_managed_vm
        payload['metadata']['appEngine'] = {
          'moduleId' => @gae_backend_name,
          'versionId' => @gae_backend_version,
          'computeEngineVmId' => @vm_id
        }
      else
        payload['metadata']['computeEngine'] = { 'instanceId' => @vm_id }
      end

      # TODO: Add in calls for creating log streams?
      chunk.msgpack_each do |row_object|
        # Ignore the extra info that can be automatically appended to the tag
        # for certain log types such as syslog.
        log_name = row_object[0].partition('.')[0]
        url = "https://www.googleapis.com/logs/v1beta/projects/#{@project_id}/logs/#{log_name}/entries"
        payload['metadata']['timeNanos'] = row_object[1] * 1000000000
        payload['textLogEntry'] = row_object[2]
        
        # TODO: Remove print statements
        puts url
        puts payload
        RestClient.post(url, payload.to_json,
                        {'Content-Type'=>'application/json'})
      end
    end

    def fetch_metadata(metadata_path)
      RestClient.get('http://metadata/computeMetadata/v1/' + metadata_path,
                     {'Metadata-Flavor' => 'Google'})
    end

    def init_payload()
    end

    def api_client
      return @client if @client && !@client.authorization.expired?

      @client = Google::APIClient.new(
        :application_name => 'Fluentd Google Cloud Logging plugin',
        # TODO: Set this from a shared configuration file.
        :application_version => '0.1.0'
      )
      @client.authorization = Google::APIClient::ComputeServiceAccount.new
      @client.authorization.fetch_access_token!
      return @client
    end
  end
end
