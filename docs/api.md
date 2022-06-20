# Documentation Module

## Exception Hierarchy

All exceptions thrown by `jbxapi.py` are subclasses of `JoeException`.

<pre>
JoeException
--> ApiError
    --> MissingParameterError
    --> InvalidParameterError
    --> InvalidApiKeyError
    --> ServerOfflineError
    --> InternalServerError
    --> PermissionError
    --> UnknownEndpointError
--> ConnectionError
</pre>

## Joe Sandbox

```python
class JoeSandbox(builtins.object)
 |  JoeSandbox(apikey=None, apiurl=None, accept_tac=None, timeout=None, verify_ssl=True, retries=3, proxies=None, user_agent=None)
 |  
 |  Methods defined here:
 |  
 |  __init__(self, apikey=None, apiurl=None, accept_tac=None, timeout=None, verify_ssl=True, retries=3, proxies=None, user_agent=None)
 |      Create a JoeSandbox object.
 |      
 |      Parameters:
 |        apikey:     the api key
 |        apiurl:     the api url
 |        accept_tac: Joe Sandbox Cloud requires accepting the Terms and Conditions.
 |                    https://jbxcloud.joesecurity.org/resources/termsandconditions.pdf
 |        timeout:    Timeout in seconds for accessing the API. Raises a ConnectionError on timeout.
 |        verify_ssl: Enable or disable checking SSL certificates.
 |        retries:    Number of times requests should be retried if they timeout.
 |        proxies:    Proxy settings, see the requests library for more information:
 |                    http://docs.python-requests.org/en/master/user/advanced/#proxies
 |        user_agent: The user agent. Use this when you write an integration with Joe Sandbox
 |                    so that it is possible to track how often an integration is being used.
 |  
 |  account_info(self)
 |      Only available on Joe Sandbox Cloud
 |      
 |      Show information about the account.
 |  
 |  analysis_delete(self, webid)
 |      Delete an analysis.
 |  
 |  analysis_download(self, webid, type, run=None, file=None, password=None)
 |      Download a resource for an analysis. E.g. the full report, binaries, screenshots.
 |      The full list of resources can be found in our API documentation.
 |      
 |      When `file` is given, the return value is the filename specified by the server,
 |      otherwise it's a tuple of (filename, bytes).
 |      
 |      Parameters:
 |          webid:    the webid of the analysis
 |          type:     the report type, e.g. 'html', 'bins'
 |          run:      specify the run. If it is None, let Joe Sandbox pick one
 |          file:     a writable file-like object (When omitted, the method returns
 |                    the data as a bytes object.)
 |          password: a password for decrypting a resource (see the
 |                    encrypt-with-password submission option)
 |      
 |      Example:
 |      
 |          name, json_report = joe.analysis_download(123456, 'jsonfixed')
 |      
 |      Example:
 |      
 |          with open("full_report.html", "wb") as f:
 |              name = joe.analysis_download(123456, "html", file=f)
 |  
 |  analysis_info(self, webid)
 |      Show the status and most important attributes of an analysis.
 |  
 |  analysis_list(self)
 |      Fetch a list of all analyses.
 |      
 |      Consider using `analysis_list_paged` instead.
 |  
 |  analysis_list_paged(self)
 |      Fetch all analyses. Returns an iterator.
 |      
 |      The returned iterator can throw an exception anytime `next()` is called on it.
 |  
 |  analysis_search(self, query)
 |      Lists the webids of the analyses that match the given query.
 |      
 |      Searches in MD5, SHA1, SHA256, filename, cookbook name, comment, url and report id.
 |  
 |  joelab_filesystem_download(self, machine, path, file)
 |      Download a file from a Joe Lab machine.
 |      
 |      Parameters:
 |          machine:  The machine id.
 |          path:     The path of the file on the Joe Lab machine.
 |          file:     a writable file-like object
 |      
 |      Example:
 |      
 |          with open("myfile.zip", "wb") as f:
 |              joe.joelab_filesystem_download("w7_10", "C:\windows32\myfile.zip", f)
 |  
 |  joelab_filesystem_upload(self, machine, file, path=None, _chunked_upload=True)
 |      Upload a file to a Joe Lab machine.
 |      
 |      Parameters:
 |        machine       The machine id.
 |        file:         The file to upload. Needs to be a file-like object or a tuple in
 |                      the shape (filename, file-like object).
 |  
 |  joelab_images_list(self, machine)
 |      List available images.
 |  
 |  joelab_images_reset(self, machine, image=None)
 |      Reset the disk image of a machine.
 |  
 |  joelab_list_exitpoints(self)
 |      List the available internet exit points.
 |  
 |  joelab_machine_info(self, machine)
 |      Show JoeLab Machine info.
 |  
 |  joelab_network_info(self, machine)
 |      Show Network info
 |  
 |  joelab_network_update(self, machine, settings)
 |      Update the network settings.
 |  
 |  joelab_pcap_download(self, machine, file)
 |      Download the captured PCAP.
 |      
 |      Parameters:
 |          machine:  The machine id.
 |          file:     a writable file-like object
 |      
 |      Example:
 |      
 |          with open("dump.pcap", "wb") as f:
 |              joe.joelab_pcap_download("w7_10", f)
 |  
 |  joelab_pcap_start(self, machine)
 |      Start PCAP recording.
 |  
 |  joelab_pcap_stop(self, machine)
 |      Stop PCAP recording.
 |  
 |  server_info(self)
 |      Query information about the server.
 |  
 |  server_languages_and_locales(self)
 |      Show the available languages and locales
 |  
 |  server_lia_countries(self)
 |      Show the available localized internet anonymization countries.
 |  
 |  server_online(self)
 |      Returns True if the Joe Sandbox servers are running or False if they are in maintenance mode.
 |  
 |  server_systems(self)
 |      Retrieve a list of available systems.
 |  
 |  submission_delete(self, submission_id)
 |      Delete a submission.
 |  
 |  submission_info(self, submission_id)
 |      Returns information about a submission including all the analysis ids.
 |  
 |  submission_list(self, **kwargs)
 |      Fetch all submissions. Returns an iterator.
 |      
 |      You can give the named parameter `include_shared`.
 |      
 |      The returned iterator can throw an exception every time `next()` is called on it.
 |  
 |  submit_cookbook(self, cookbook, params={}, _extra_params={})
 |      Submit a cookbook.
 |  
 |  submit_sample(self, sample, cookbook=None, params={}, _extra_params={}, _chunked_upload=True)
 |      Submit a sample and returns the submission id.
 |      
 |      Parameters:
 |        sample:       The sample to submit. Needs to be a file-like object or a tuple in
 |                      the shape (filename, file-like object).
 |        cookbook:     Uploads a cookbook together with the sample. Needs to be a file-like object or a
 |                      tuple in the shape (filename, file-like object)
 |        params:       Customize the sandbox parameters. They are described in more detail
 |                      in the default submission parameters.
 |      
 |      Example:
 |      
 |          import jbxapi
 |      
 |          joe = jbxapi.JoeSandbox(user_agent="My Integration")
 |          with open("sample.exe", "rb") as f:
 |              joe.submit_sample(f, params={"systems": ["w7"]})
 |      
 |      Example:
 |      
 |          import io, jbxapi
 |      
 |          joe = jbxapi.JoeSandbox(user_agent="My Integration")
 |      
 |          cookbook = io.BytesIO(b"cookbook content")
 |          with open("sample.exe", "rb") as f:
 |              joe.submit_sample(f, cookbook=cookbook)
 |  
 |  submit_sample_url(self, url, params={}, _extra_params={})
 |      Submit a sample at a given URL for analysis.
 |  
 |  submit_url(self, url, params={}, _extra_params={})
 |      Submit a website for analysis.
 |
 |  submit_command_line(self, command_line, params={}, _extra_params={})
 |      Submit a command line to be executed with cmd.exe
  
