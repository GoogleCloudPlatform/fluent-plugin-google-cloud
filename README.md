fluent-plugin-google-cloud
==========================

Plugin for Fluentd that sends logs to the Google Cloud Platform's logs API.

This plugin currently only supports being run on a Google Compute Engine VM because it grabs its authentication token as well as important metadata from the VM metadata server.

Note that for testing this plugin without needing to install it as a gem, you can just copy it to /etc/fluent/plugin/, and Fluentd will automatically load it.
