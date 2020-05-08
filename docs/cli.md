# Documentation CLI

## Parameters

The script requires that you pass some parameters. Choose the option which works best for you.

* Pass the API url and API key on on the command line:

    ```bash
    >>> jbxapi --apiurl https://joesandbox.example.net --apikey abc...xyz --accept-tac
    ```

* Use the environment variables `JBX_API_KEY`, `JBX_API_URL` and `JBX_ACCEPT_TAC=1`.
* Modify the variables `API_KEY`, `API_URL` and `ACCEPT_TAC` directly inside the Python script.

## Built-in help

```bash
>>> jbxapi --help
usage: jbxapi [-h] <command> ...

Joe Sandbox Web API

optional arguments:
  -h, --help  show this help message and exit

commands:
  <command>
    submit      Submit a sample to Joe Sandbox.
    submission  Manage submissions
    analysis    Manage analyses
    server      Query server info
```

```bash
>>> .\jbxapi submission --help
usage: jbxapi.py submission [-h] <submission command> ...

optional arguments:
  -h, --help            show this help message and exit

submission commands:
  <submission command>
    info                Show info about a submission.
    delete              Delete a submission.
```

## Submitting samples

### Samples

```bash
>>> jbxapi submit 67.0939148037769.docx
{
    "submission_id": "140"
}
```

### URLs

```bash
>>> jbxapi submit --url http://example.net
{
    "submission_id": "140"
}
```

## Getting information about an submission

The submission id can be used to track the status:

```bash
>>> jbxapi submission info 140
{
    "submission_id": "140",
    "name": "Sample.exe",
    "status": "finished",
    "time": "2019-04-15T08:05:05+00:00",

    "most_relevant_analysis": {
        "webid": "179"
        "detection": "clean",
        "score": 30
    },

    "analyses": [
        {
            "webid": "179",
            "time": "2019-04-15T08:05:08+00:00",
            "runs": [
                {
                    "detection": "clean",
                    "error": null,
                    "system": "w7",
                    "yara": false
                },
                {
                    "detection": "clean",
                    "error": null,
                    "system": "w7x64",
                    "yara": false
                }
            ],
            "tags": [],
            "analysisid": "127",
            "duration": 1,
            "md5": "098f6bcd4621d373cade4e832627b4f6",
            "sha1": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
            "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "filename": "Sample.exe",
            "scriptname": "defaultwindowsofficecookbook.jbs",
            "status": "finished",
            "comments": ""
        }, {
            "webid": "180",
            ...
        }
    ]
}
```

## Download reports and analysis artifacts

Once the `status` is `finished`, you can download various reports and analysis artifacts using the webid of the analyses:

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
>>> jbxapi analysis report 180
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
jbxapi analysis search docx
[
    {
        "webid": "180"
    }
]
```

The search API also accepts MD5 and SHA file hashes, file names, comments etc.
