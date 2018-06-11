![JoeSandboxCloud](img/logo.png)

# API Wrapper

The Joe Sandbox Cloud API Wrapper enables you to fully integrate [Joe Sandbox Cloud](https://www.joesecurity.org/joe-sandbox-cloud) into your malware analysis framework. Joe Sandbox Cloud is a deep malware analysis platform which detects malicious files. 

It is at the same time a powerful implementation of the Joe Sandbox API and also a command line tool for interacting with Joe Sandbox.

# License

The code is written in Python and licensed under MIT.

# Requirements

* Python 2.7 or higher

# Installation

## With Pip

    pip install jbxapi

## Manually

1. Install [python-requests](http://docs.python-requests.org/en/latest/)

        pip install python-request

2. Copy `jbxapi.py` to where you need it.

## Parameters

You can pass the api key to the script and agree to the Joe Sandbox Cloud terms and conditions
by passing `--apikey <key>` and `--accept-tac` or modify the following variables inside the
script:

```python
# APIKEY, to generate goto user settings - API key
API_KEY = ""

# Set to True if you agree to the Terms and Conditions.
ACCEPT_TAC  = False
```

# Documentation CLI

## Built-in help

```bash
>>> jbxapi --help
usage: jbxapi [-h] <command> ...

Joe Sandbox Web API

optional arguments:
  -h, --help  show this help message and exit

commands:
  <command>
    list      Show all submitted analyses.
    submit    Submit a sample to Joe Sandbox.
    info      Show info about an analysis.
    delete    Delete an analysis.
    report    Print the irjsonfixed report.
    download  Download a resource of an analysis.
    search    Search for analysis.
    systems   List all available systems.
    server    Query server info
```

```bash
>>> .\jbxapi info --help
usage: jbxapi info [-h] [--apiurl APIURL] [--apikey APIKEY] [--accept-tac]
                      webid

positional arguments:
  webid            Webid of the analysis.

optional arguments:
  -h, --help       show this help message and exit
  --apiurl APIURL  Api Url (You can also modify the API_URL variable inside
                   the script.)
  --apikey APIKEY  Api Key (You can also modify the API_KEY variable inside
                   the script.)
  --accept-tac     (Joe Sandbox Cloud only): Accept the terms and conditions:
                   https://jbxcloud.joesecurity.org/download/termsandcondition
                   s.pdf (You can also modify the ACCEPT_TAC variable inside
                   the script.)
```

## Starting an analysis

### Samples

```bash
>>> jbxapi submit 67.0939148037769.docx
{
    "webids": ["251231"]
}
```

### URLs

```bash
>>> jbxapi submit --url http://example.net
{
    "webids": ["265270"]
}
```

## Getting information about an analysis

The web ID can be used to track the status:

```bash
>>> jbxapi info 265270
{
    "webid": "265270"
    "status": "finished",
    "time": "2017-09-11T17:32:06+02:00",
    "comments": "",
    "filename": "67.0939148037769.docx",
    "scriptname": "default.jbs",
    "md5": "0cbc6611f5540bd0809a388dc95a615b",
    "sha1": "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa",
    "sha256": "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25",
    "runs": [{
        "detection": "malicious",
        "error": null,
        "system": "w7",
        "yara": false
    }],
}
```

## Download reports and analysis artifacts

Once the `status` is `finished`, you can download various reports and analysis artifacts:

* HTML
* PDF
* JSON
* XML
* Light HTML, JSON and XML
* Executive report
* Incident report
* [MAEC report](https://maec.mitre.org/)
* [MISP report](http://www.misp-project.org/)
* [OpenIOC report](http://www.openioc.org/)
* Graph report
* Dropped binaries
* Screenshots
* Binary strings
* Memory strings
* PCAP of network traffic
* Unpacked PE files
* Memory dumps 
* [IDA Pro](https://www.hex-rays.com) bridge files
* Generated [Yara](https://virustotal.github.io/yara/) rules
* Sample
* Cookbook

```bash
>>> jbxapi report 262018
{
    "analysis": {
        "arch": "WINDOWS",
        "confidence": {
            "expertadviceneeded": false,
            "maxscore": 5,
            "minscore": 0,
            "score": 5
        },
        "contacted": {
            "domains": null,
            "ips": {
                "ip": [
                    {
                        "$": "185.195.25.79",
                        "@malicious": "true"
...
```

Search for an analysis:

```json
jbxapi search docx
[
    {
        "webid": "262018"
    }
]
```

The search API also accepts MD5 and SHA file hashes, file names, comments etc.

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
--> ConnectionError
</pre>

## Joe Sandbox

```python
class JoeSandbox(object)

    __init__(self, apikey='', apiurl='https://jbxcloud.joesecurity.org/api',
                   accept_tac=False, timeout=None, verify_ssl=True, retries=3)
        Create a JoeSandbox object.

        Parameters:
          apikey:     the api key
          apiurl:     the api url
          accept_tac: Joe Sandbox Cloud requires accepting the Terms and Conditions.
                      https://jbxcloud.joesecurity.org/resources/termsandconditions.pdf
          timeout:    Timeout in seconds for accessing the API. Raises a ConnectionError on timeout.
          verify_ssl: Enable or disable checking SSL certificates.
          retries:    Number of times requests should be retried if they timeout.

    account_info(self)
        Only available on Joe Sandbox Cloud

        Show information about the account.

    delete(self, webid)
        Delete an analysis.

    download(self, webid, type, run=None, file=None)
        Download a resource for an analysis. E.g. the full report, binaries, screenshots.
        The full list of resources can be found in our API documentation.

        When `file` is given, the return value is the filename specified by the server,
        otherwise its a tuple of (filename, bytes) with the filename and the content.

        Parameters:
            webid: the webid of the analysis
            type: the report type, e.g. 'html', 'bins'
            run: specify the run. If it is None, let Joe Sandbox pick one
            file: a writeable file-like object (When obmitted, the method returns
                  the data as a bytes object.)

        Example:

            json_report = joe.download(123456, 'jsonfixed')

        Example:

            with open("full_report.html", "wb") as f:
                joe.download(123456, "html", file=f)

    info(self, webid)
        Show the status and most important attributes of an analysis.

    list(self)
        Fetch a list of all analyses.

    search(self, query)
        Lists the webids of the analyses that match the given query.

        Searches in MD5, SHA1, SHA256, filename, cookbook name, comment, url and report id.

    server_info(self)
        Query information about the server.

    server_lia_countries(self)
        Show the available localized internet anonymization countries.

    server_online(self)
        Returns True if the Joe Sandbox servers are running or False if they are in maintenance mode.

    submit_cookbook(self, cookbook, params={})
        Submit a cookbook.

    submit_sample(self, sample, cookbook=None, params={})
        Submit a sample and returns the associated webids for the samples.

        Parameters:
          sample:       The sample to submit. Needs to be a file-like object.
          cookbook:     Uploads a cookbook together with the sample.
          params:       Customize the sandbox parameters. They are described in more detail
                        in the default submission parameters.

        Example:

            joe = JoeSandbox()
            with open("sample.exe", "rb") as f:
                joe.submit_sample(f, params={"systems": ["w7"]})

        Example:

            import io.BytesIO
            joe = JoeSandbox()

            cookbook = io.BytesIO(b"cookbook content")
            with open("sample.exe", "rb") as f:
                joe.submit_sample(f, cookbook=cookbook)

    submit_sample_url(self, url, params={})
        Submit a sample at a given URL for analysis.

    submit_url(self, url, params={})
        Submit a website for analysis.

    systems(self)
        Retrieve a list of available systems.
```

# Credits

* Thanks to [Pedram Amini](https://github.com/pedramamini) for a first wrapper implementation!

# Links

* [Joe Sandbox Cloud](https://www.joesecurity.org/joe-sandbox-cloud)

# Author

Joe Security LLC (@[joe4security](https://twitter.com/#!/joe4security) - [webpage](https://www.joesecurity.org))

