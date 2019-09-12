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
--> ConnectionError
</pre>

## Joe Sandbox

```python
class JoeSandbox(object)

    __init__(self, apikey='', apiurl='https://jbxcloud.joesecurity.org/api',
                   accept_tac=False, timeout=None, verify_ssl=True, retries=3, proxies=None)
        Create a JoeSandbox object.
        
        Parameters:
          apikey:     the api key
          apiurl:     the api url
          accept_tac: Joe Sandbox Cloud requires accepting the Terms and Conditions.
                      https://jbxcloud.joesecurity.org/resources/termsandconditions.pdf
          timeout:    Timeout in seconds for accessing the API. Raises a ConnectionError on timeout.
          verify_ssl: Enable or disable checking SSL certificates.
          retries:    Number of times requests should be retried if they timeout.
          proxies:    Proxy settings, see the requests library for more information:
                      http://docs.python-requests.org/en/master/user/advanced/#proxies
    
    account_info(self)
        Only available on Joe Sandbox Cloud
        
        Show information about the account.
    
    analysis_delete(self, webid)
        Delete an analysis.
    
    analysis_download(self, webid, type, run=None, file=None)
        Download a resource for an analysis. E.g. the full report, binaries, screenshots.
        The full list of resources can be found in our API documentation.
        
        When `file` is given, the return value is the filename specified by the server,
        otherwise it's a tuple of (filename, bytes).
        
        Parameters:
            webid: the webid of the analysis
            type: the report type, e.g. 'html', 'bins'
            run: specify the run. If it is None, let Joe Sandbox pick one
            file: a writeable file-like object (When obmitted, the method returns
                  the data as a bytes object.)
        
        Example:
        
            name, json_report = joe.analysis_download(123456, 'jsonfixed')
        
        Example:
        
            with open("full_report.html", "wb") as f:
                name = joe.analysis_download(123456, "html", file=f)
    
    analysis_info(self, webid)
        Show the status and most important attributes of an analysis.
    
    analysis_list(self)
        Fetch a list of all analyses.
    
    analysis_search(self, query)
        Lists the webids of the analyses that match the given query.
        
        Searches in MD5, SHA1, SHA256, filename, cookbook name, comment, url and report id.
    
    server_info(self)
        Query information about the server.
    
    server_languages_and_locales(self)
        Show the available languages and locales
    
    server_lia_countries(self)
        Show the available localized internet anonymization countries.
    
    server_online(self)
        Returns True if the Joe Sandbox servers are running or False if they are in maintenance mode.
    
    server_systems(self)
        Retrieve a list of available systems.
    
    submission_delete(self, submission_id)
        Delete a submission.
    
    submission_info(self, submission_id)
        Returns information about a submission including all the analysis ids.
    
    submit_cookbook(self, cookbook, params={}, _extra_params={})
        Submit a cookbook.
    
    submit_sample(self, sample, cookbook=None, params={}, _extra_params={})
        Submit a sample and returns the submission id.
        
        Parameters:
          sample:       The sample to submit. Needs to be a file-like object or a tuple in
                        the shape (filename, file-like object).
          cookbook:     Uploads a cookbook together with the sample. Needs to be a file-like object or a
                        tuple in the shape (filename, file-like object)
          params:       Customize the sandbox parameters. They are described in more detail
                        in the default submission parameters.
        
        Example:
        
            import jbxapi
        
            joe = jbxapi.JoeSandbox()
            with open("sample.exe", "rb") as f:
                joe.submit_sample(f, params={"systems": ["w7"]})
        
        Example:
        
            import io, jbxapi
        
            joe = jbxapi.JoeSandbox()
        
            cookbook = io.BytesIO(b"cookbook content")
            with open("sample.exe", "rb") as f:
                joe.submit_sample(f, cookbook=cookbook)
    
    submit_sample_url(self, url, params={}, _extra_params={})
        Submit a sample at a given URL for analysis.
    
    submit_url(self, url, params={}, _extra_params={})
        Submit a website for analysis.
```
