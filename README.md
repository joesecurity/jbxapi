![JoeSandboxCloud](https://raw.githubusercontent.com/joesecurity/joesandboxcloudapi/master/img/cloudlogo.png)

# API Wrapper

The Joe Sandbox Cloud API Wrapper enables you to fully integrate [Joe Sandbox Cloud](https://www.joesecurity.org/joe-sandbox-cloud) into your malware analysis framework. Joe Sandbox Cloud is a deep malware analysis platform which detects malicious files. 

So far the following actions are implemented:

* Check if Joe Sandbox Cloud is available
* Check queue size
* List all analysis machines
* Submit a sample
* Submit a sample with cookbook
* Check the status of an analysis
* Download analysis reports
* List all analyses
* Search for analyses 
* Delete analyses
* Query daily and monthly quota
* Query account type

The API is implemented as a Python class "joe_api" that you can call on the command line or import into your project. joe_api contains less than 300 LOC and is very concise and easy to understand.  

# License

The code is written in Python and licensed under MIT.

# Requirements

* Python 2.6 or higher
* [python-requests](http://docs.python-requests.org/en/latest/), pip install python-requests

# Install

Add your API key and accept the Joe Sandbox Cloud terms and conditions:

```python
# APIKEY, to generate goto user settings - API key
JOE_APIKEY = ""

# SET TO TRUE IF AGREE TO TERMS (settings in the web interface do not apply to this configuration)
JOE_TAC  = False
```

# Examples

To list all commands call jbxapi.py without any arguments:

```bash
jbxapi.py
Joe Sandbox Web API implementation v2.0.0
jbxapi.py: <analyses | analyze <filepath> | available | status <id> | delete <id
> | queue | report <id> | search <term> | systems>
```

Sumbit a sample: 

```bash
jbxapi.py analyze 67.0939148037769.docx
{
    "webid": 265270,
    "webids": [
        265270
    ]
}
```

The web ID can be used to track the status:
```bash
jbxapi.py status 265270
{
    "comments": "",
    "detections": "",
    "errors": "",
    "filename": "67.0939148037769.docx",
    "md5": "cb87cadf363eee6d9148adcd7cc6f7fd",
    "reportid": "-1",
    "runnames": "",
    "scriptname": "defaultwindowsofficecookbook.jbs",
    "sha1": "a09f94df46b81661dfdda33c2e93727de8dfa027",
    "sha256": "b0b1c2c6a54ad214183739edc1c3ce22c7dbe465e93ac1b3375e8bf17176ba38",
    "status": "running",
    "systems": "",
    "time": "1493036543",
    "webid": "265270",
    "yara": ""
}
```

Check for the field "status" = "finished". Once the status is "finished" you can download various reports and analysis artifacts:

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
* PCAP of network traffice
* Unpacked PE files
* Memory dumps 
* [IDA Pro](https://www.hex-rays.com) bridge files
* Generated [Yara](https://virustotal.github.io/yara/) rules
* Sample
* Cookbook

By default the incident report is downloaded:

```json

C:\Users\admin\Desktop>python jbxapi.py report 262018
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
                    }
                ]
            }
        },
        "cookbook": "defaultwindowsofficecookbook.jbs",
        "detection": {
            "clean": false,
            "malicious": true,
            "maxscore": 100,
            "minscore": 0,
            "score": 84,
            "suspicious": false,
            "unknown": false
        },
        "dropped": {
            "file": [
                {
                    "malicious": true,
                    "md5": "CB8C8356D0A96E63529B332C50B0EC43",
                    "name": "C:\\Users\\LUKETA~1\\AppData\\Local\\Temp\\MS WordDocument Open.vbs",
                    "sha1": "E6313518E7F3B7F87EC3FCC24665FEFB1FEDECE3",
                    "sha256": "2569127F96913D9A76F44AB0076BC6DA9CC88F261D9C8B610F10D7104E263218"
                },
                {
                    "malicious": false,
                    "md5": "F2A117AE004B1DE41F5A7D6D52FAFC97",
                    "name": "C:\\Users\\luketaylor\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.IE5\\GNNUVO51\\5324[1].csv",
                    "sha1": "ECEBE78B87629E542BC2C5B4DA767B4D5085CBAC",
                    "sha256": "84F93DFF21108CD962BD075C0303C87A81A5066C4BCE82CB06FE41A1FE4E8059"
                },
                {
                    "malicious": false,
                    "md5": "F2A117AE004B1DE41F5A7D6D52FAFC97",
                    "name": "C:\\Users\\luketaylor\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.IE5\\GNNUVO51\\5324[2].csv",
                    "sha1": "ECEBE78B87629E542BC2C5B4DA767B4D5085CBAC",
                    "sha256": "84F93DFF21108CD962BD075C0303C87A81A5066C4BCE82CB06FE41A1FE4E8059"
                },
                {
                    "malicious": false,
                    "md5": "E4D62B80BDA10691C084DBA36B1230B2",
                    "name": "C:\\Users\\luketaylor\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.MSO\\25BCF926.png",
                    "sha1": "D36B9014A3EA2EB5013C3EC7BCBB69B9F0E79989",
                    "sha256": "9DE0C4096B42A54336A08DAEDD2D479308CD53475CEEAC3953F9596BBE1BD317"
                },
            ]
        },
        "errors": "",
        "filetype": "Generic OLE2 / Multistream Compound File (8008/1) 100.00%",
        "hashes": {
            "md5": "cb87cadf363eee6d9148adcd7cc6f7fd",
            "sha1": "a09f94df46b81661dfdda33c2e93727de8dfa027",
            "sha256": "b0b1c2c6a54ad214183739edc1c3ce22c7dbe465e93ac1b3375e8bf17176ba38"
        },
        "id": 255275,
        "reporttype": "IR",
        "sample": "67.0939148037769.docx",
        "signatures": {
            "signare": [
                "Document contains encrypted data (likely password protected)",
                "Document exploit detected (process start blacklist hit)",
                "Drops files with a non-matching file extension (content does not match file extension)",
                "Potential malicious VBS script found (has network functionality)",
                "Potential malicious VBS script found (suspicious strings)",
                "Benign windows process drops PE files",
                "Document exploit detected (creates forbidden files)",
                "System process connects to network (likely due to code injection or exploit)"
            ]
        },
        "startdate": "18/04/2017",
        "starttime": "10:27:48",
        "system": "Windows 7 (Office 2010 v14.0.4, Java 1.8.0_40, Flash 16.0.0.305, Acrobat Reader 11.0.08, Internet Explorer 11, Chrome 55, Firefox 43)",
        "version": "18.0.0"
    }
}
```

Please note that not all reports are in JSON format. 

Search for an analysis:

```json
jbxapi.py search docx
[
    {
        "comments": "",
        "detections": "1;",
        "errors": "",
        "filename": "ENDBENUTZER.docx",
        "md5": "63c944c9aa63b2be05ac25d962ab9595",
        "mostInterestingRun": 0,
        "numberofruns": 2,
        "reportid": "136487",
        "runnames": ";",
        "scriptname": "defaultwindowsdocumentcookbook.jbs",
        "sha1": "c848ea697e8c015d8a37bd201940020720d684e4",
        "sha256": "048d242f37542aa1e815f410e098834e9ded07c50c097d24f38551a9e47afbb1",
        "status": "finished",
        "systems": "xp;",
        "time": "1466543393",
        "user_ref": "1",
        "webid": "140070",
        "yara": "false;"
    },
    {
        "comments": "",
        "detections": "2;",
        "errors": "",
        "filename": "4fd53f748006c7f7729cd3360ec8a9a50740e253cb2583f5330fd5e35b64cb04.docx",
        "md5": "1397c911257c53455b0951f0ab40b3b5",
        "mostInterestingRun": 0,
        "numberofruns": 2,
```

The search API also accepts MD5 and SHA file hashes, filenames, comments etc.

# Existing Integrations

* [MISP](https://github.com/MISP/MISP)
* [Fame](https://github.com/certsocietegenerale/fame)
* [TheHive](https://github.com/CERT-BDF/TheHive)

# Credits

* Thanks to [Pedram Amini](https://github.com/pedramamini) for a first wrapper implementation!

# Links

* [Joe Sandbox Cloud](https://www.joesecurity.org/joe-sandbox-cloud)

# Author

Joe Security (@[joe4security](https://twitter.com/#!/joe4security) - [webpage](https://www.joesecurity.org))

