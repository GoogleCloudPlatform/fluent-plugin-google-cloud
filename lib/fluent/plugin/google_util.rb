# Copyright 2016 Google Inc. All rights reserved.
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
require 'yaml'
require 'googleauth'
require 'googleauth/stores/file_token_store'

module Fluent
  # Utilities used by the Google Cloud Logging plugin.
  module GoogleUtil
    # "enum" of Platform values
    module Platform
      OTHER = 0  # Other/unkown platform
      GCE = 1    # Google Compute Engine
      EC2 = 2    # Amazon EC2
    end

    # Extended metadata returned by the detect_metadata method.
    ExtendedMetadata = Struct.new(
      :gae_backend_name,
      :gae_backend_version,
      :dataflow_job_id,
      :kube_cluster_name,
      :gcf_region,
      :ec2_account_id)

    # The MetadataMixin module adds metadata reading to a google fluentd plugin.
    # It contains constants for the service names, and common attributes
    # TODO: Factor per-enum data into different classes?
    # Expects: an @log instance variable.
    module MetadataMixin
      # Constants for service names.
      APPENGINE_SERVICE = 'appengine.googleapis.com'
      CLOUDFUNCTIONS_SERVICE = 'cloudfunctions.googleapis.com'
      COMPUTE_SERVICE = 'compute.googleapis.com'
      CONTAINER_SERVICE = 'container.googleapis.com'
      DATAFLOW_SERVICE = 'dataflow.googleapis.com'
      EC2_SERVICE = 'ec2.amazonaws.com'

      # Project/instance metadata.
      #
      # Read/write attributes, generally filled in when @use_metadata_service
      # is true, but may be overridden by a plugin using, e.g. config
      # information.
      attr_accessor :project_id
      attr_accessor :zone
      attr_accessor :vm_id
      attr_accessor :vm_name
      attr_accessor :component

      # Read-only, based on the platform and detected values.
      attr_reader :service_name
      attr_reader :platform

      # The logger instance, used by detect_platform
      attr_accessor :log

      # detect_metadata attempts to detect the common metadata. Fills in missing
      # attribute values.
      #
      # Args:
      # - use_metadata_service: boolean
      #     Whether to attempt to obtain metadata from the
      #     local metadata service. It is safe to specify 'true' even in
      #     environments with no metadata service.
      # - detect_subservice: boolean
      #     Whether to try to detect if the VM is owned by a "subservice", such
      #     as AppEngine or Kubernetes. Has no effect when not running on GCE.
      #
      # Returns an ExtendedMetadata with attributes set.
      def detect_metadata(use_metadata_service, detect_subservice)
        # set attributes from metadata (unless overriden by static config)
        @vm_name = Socket.gethostname if @vm_name.nil?

        if use_metadata_service
          @platform = detect_platform
        else
          @platform = Platform::OTHER
        end

        extended = nil

        case @platform
        when Platform::GCE
          @service_name = COMPUTE_SERVICE
          if @project_id.nil? && use_metadata_service
            @project_id = fetch_gce_metadata('project/project-id')
          end
          if @zone.nil?
            # this returns "projects/<number>/zones/<zone>"; we only want
            # the part after the final slash.
            fully_qualified_zone = fetch_gce_metadata('instance/zone')
            @zone = fully_qualified_zone.rpartition('/')[2]
          end
          @vm_id = fetch_gce_metadata('instance/id') if @vm_id.nil?

          if detect_subservice
            # Check for specialized GCE environments.
            # TODO: Add config options to set these outside of GCE?
            attributes = fetch_gce_metadata('instance/attributes/').split
            # Do nothing, just don't populate other service's labels.
            if attributes.include?('gae_backend_name') &&
               attributes.include?('gae_backend_version')
              # Managed VM
              @service_name = APPENGINE_SERVICE
              extended = ExtendedMetadata.new
              extended.gae_backend_name = fetch_gce_metadata(
                'instance/attributes/gae_backend_name')
              extended.gae_backend_version = fetch_gce_metadata(
                'instance/attributes/gae_backend_version')
            elsif attributes.include?('job_id')
              # Dataflow
              @service_name = DATAFLOW_SERVICE
              extended = ExtendedMetadata.new
              extended.dataflow_job_id = fetch_gce_metadata(
                'instance/attributes/job_id')
            elsif attributes.include?('gcf_region') &&
                  attributes.include?('kube-env')
              # CloudFunctions
              @service_name = CLOUDFUNCTIONS_SERVICE
              extended = ExtendedMetadata.new
              extended.gcf_region = fetch_gce_metadata(
                'instance/attributes/gcf_region')
              extended.kube_cluster_name = kube_cluster_name
            elsif attributes.include?('kube-env')
              # Kubernetes/Container Engine
              @service_name = CONTAINER_SERVICE
              extended = ExtendedMetadata.new
              extended.kube_cluster_name = kube_cluster_name
              # TODO: Augment with common kubernetes fields.
              # namespace_name pod_name container_name
            end
          end

        when Platform::EC2
          @service_name = EC2_SERVICE
          metadata = fetch_ec2_metadata
          if @zone.nil? && metadata.key?('availabilityZone')
            @zone = 'aws:' + metadata['availabilityZone']
          end
          if @vm_id.nil? && metadata.key?('instanceId')
            @vm_id = metadata['instanceId']
          end
          if metadata.key?('accountId')
            extended = ExtendedMetadata.new
            extended.ec2_account_id = metadata['accountId']
          end

        when Platform::OTHER
          @service_name = COMPUTE_SERVICE

        else
          fail Fluent::ConfigError, 'Unknown platform ' + @platform
        end

        extended
      end

      private

      # Address of the metadata service.
      METADATA_SERVICE_ADDR = '169.254.169.254'

      # Determine what platform we are running on by consulting the metadata
      # service (unless the user has explicitly disabled using that).
      def detect_platform
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
          @log.debug "Failed to access metadata service: #{e}"
        end

        @log.info 'Unable to determine platform'
        Platform::OTHER
      end

      # Read metadata from the GCE metadata service.
      def fetch_gce_metadata(metadata_path)
        fail "Called fetch_gce_metadata with platform=#{@platform}" unless
          @platform == Platform::GCE
        # See https://cloud.google.com/compute/docs/metadata
        open('http://' + METADATA_SERVICE_ADDR + '/computeMetadata/v1/' +
             metadata_path, 'Metadata-Flavor' => 'Google', &:read)
      end

      # Read metadata from the EC2 metadata service.
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

      # Return the cluster name from the kube-env metadata
      def kube_cluster_name
        raw_kube_env = fetch_gce_metadata('instance/attributes/kube-env')
        kube_env = YAML.load(raw_kube_env)
        return kube_env['CLUSTER_NAME'] if kube_env.key?('CLUSTER_NAME')
        instance_prefix = kube_env['INSTANCE_PREFIX']
        gke_name_match = /^gke-(.+)-[0-9a-f]{8}$/.match(instance_prefix)
        return gke_name_match.captures[0] \
          if gke_name_match && !gke_name_match.captures.empty?
        instance_prefix
      end
    end # module MetadataMixin

    # The CredentialsMixin module adds Google credentials / auth to a
    # fluentd plugin.
    module CredentialsMixin
      # Parameters to configure authentication and authorization. One
      # of the methods must be configured when not running on GCE.
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
      attr_accessor :service_credentials_path

      # Returns the credentials object for the provided scope
      def get_credentials(scope)
        unless @credentials
          @credentials = get_service_credentials(scope) ||
                         Google::Auth.get_application_default(scope)
        end
        @credentials
      end

      private

      def get_service_credentials(scope)
        return unless @service_credentials_path
        File.open(@service_credentials_path) do |f|
          return Google::Auth::DefaultCredentials.make_creds(
            json_key_io: f, scope: scope)
        end
      end

      # Returns whether the credentials have expired
      def credentials_expired?
        !@credentials.access_token || @credentials.expired?
      end

      def authorize
        return unless credentials_expired?
        begin
          @credentials.fetch_access_token!
        rescue MultiJson::ParseError
          # Workaround an issue in the API client; re-raise a more
          # descriptive error for the user (which will still cause a retry).
          raise Google::APIClient::ClientError, 'Unable to fetch access ' \
            'token (no scopes configured?)'
        end
      end

      # Extract project_id from credentials?
      def project_id_from_credentials
        return nil unless @credentials
        if @credentials.issuer
          id = extract_project_id(@credentials.issuer)
          return id unless id.nil?
        end
        if @credentials.client_id
          id = extract_project_id(@credentials.client_id)
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
      def extract_project_id(str)
        [/^.*@(?<project_id>.+)\.iam\.gserviceaccount\.com/,
         /^(?<project_id>\d+)-/].each do |exp|
          match_data = exp.match(str)
          return match_data['project_id'] unless match_data.nil?
        end
        nil
      end
    end # module CredentialsMixin
  end # module GoogleUtil
end # module Fluent
