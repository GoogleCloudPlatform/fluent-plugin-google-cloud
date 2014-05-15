module Fluent
  class GoogleCloudOutput < BufferedOutput
    Fluent::Plugin.register_output('google_cloud', self)

    def initialize
      super
      require 'google/api_client'
      require 'google/api_client/auth/compute_service_account'
    end

    def configure(conf)
      super
    end

    def start
      super

      @client = nil
      # TODO: Uncomment when the logging API exists
      #@api = api_client().discovered_api('logs', 'v1')
      puts api_client()
    end

    def shutdown
      super
    end

    def format(tag, time, record)
      [time, record['message']].to_msgpack
    end

    def write(chunk)
      # TODO: Construct the payload and actually send the logs to the API
      puts api_client()
      chunk.msgpack_each do |row_object|
        puts "Time: #{row_object[0]}"
        puts row_object[1]
      end
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
