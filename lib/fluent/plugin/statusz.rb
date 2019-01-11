# Copyright 2019 Google Inc. All rights reserved.
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

# Module for collecting diagnostic information and formatting it as an
# HTML page to serve on the /statusz endpoint.
module Statusz
  module_function

  def response
    # TODO(davidbtucker): Add more status information here.
    [
      '<html>',
      '<body>',
      '<h1>Status</h1>',
      "<b>Command-line flags:</b> #{CGI.escapeHTML(ARGV.join(' '))}",
      '</body>',
      '</html>'
    ].join("\n") + "\n"
  end
end
