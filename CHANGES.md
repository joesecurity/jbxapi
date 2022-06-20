# Version 3.18.0

* Added command line submission type

# Version 3.17.2

* Removed `static-only` parameter
* Renamed `remote assistance` to `live interaction`

# Version 3.17.1

* Updated the API documentation.
* Removed the `static-only` parameter.

# Version 3.17.0

* Removal of `remote-assistance-view-only`.

# Version 3.16.0

* Add submission parameter `priority` for on-premise installations.

# Version 3.15.0

* Add parameter `include_shared` to `submission/list` endpoint.

# Version 3.14.0

* Add parameter for choosing the browser.

# Version 3.13.0

* Fix Joe Lab file upload.
* Deprecate parameter "anti-evasion-date"
* Add parameter "system-date"

# Version 3.12.0

* Joe Lab file upload uses chunked submissions now.

# Version 3.11.0

* Improve submission code to upload large samples through chunked upload.

# Version 3.10.0

* Add `submission/list` endpoint to CLI and API.

# Version 3.9.0

* Fix `joelab network update` CLI command.
* Add `joelab pcap` commands to the API and the CLI.

# Version 3.8.0

* Add `account info` command to CLI.

# Version 3.7.1

* In version 3.7, the CLI did not check the certificates unless `--no-check-certificate` was enabled.
* Documentation fix for `Joe.joelab_images_reset`

# Version 3.5, 3.6, 3.7

* Implementation of the Joe Lab API
* New dotnet-tracing parameter.
* Renamed `office-files-password` to `document-password`
* Help message improvements
* CLI gets new `--no-check-certificate` flag for easier integration in test environments.

# Version 3.4

Support environmental variables for the server settings. The variables are:

| variable              | description                                  |
| --------------------- | -------------------------------------------- |
| `JBX_API_KEY`         | Sets the api key                             |
| `JBX_API_URL`         | Sets the api url                             |
| `JBX_ACCEPT_TAC=1`    | Accept the terms and conditions (Cloud only) |

These environmental variables work in both the API and CLI interface. The order of precedence is from least to most important:

 1. variables defined directly in the Python script
 2. environmental variables
 3. arguments passed as an argument (API) or parameter (CLI)

# Version 3.3

Support for the new submission option `encrypt-with-password` and for downloading encrypted analyses.

The decryption happens transparently.

* CLI has a new option `--encrypt-with-password` for submissions.
* CLI can specify `--password` when downloading resources
* The API `JoeSandbox.analysis_download()` has a new argument `password`.

# Version 3.2

Add `--ignore-errors` flag to the "analysis download" command.

# Version 3.1.3

Add compatibility with urllib3 < 1.25.2 to avoid dependency issues.

# Version 3.1.2

The constructor of `JoeSandbox` gains a new argument `user_agent`. When you develop an integration
with Joe Sandbox, please specify the name of the integration.

# Version 3.1.1

Small fix.

# Version 3.1

Update dependencies to requests 2.22.0 and urllib 1.25.2.
This allows uploading files with non-ascii names. Closes issue #10.

Python 3.4 is no longer supported.

# Version 3.0.2

Fix the command line for `analysis report` and `analysis download`.

# Version 3.0.1

* Add `JoeSandbox.analysis_list_paged()`. Use this new method for iterating over large numbers of analyses.

# Version 3.0.0

## Breaking Change

We have added "Submission" as a new entity to our object model. Each submission can
result in one or more analyses, which is especially relevant for emails and archives.
Therefore, submissions are now the main endpoint to communicate with.

`jbxapi.py` now uses `/api/v2/submission/new` instead of `/api/v2/analysis/submit`
which results in some breaking changes.

Changes to Python class `JoeSandbox`:

| Old                                | New                                                |
| -------------                      | -------------------------------------------------- |
| `def submit_sample`                | Returns a submission id instead of multiple webids |
| `def submit_url`                   | Returns a submission id instead of multiple webids |
| `def submit_cookbook`              | Returns a submission id instead of multiple webids |
| `def info`                         | `def analysis_info`                                |
| `def delete`                       | `def analysis_delete`                              |
| `def list`                         | `def analysis_list`                                |
| `def search`                       | `def analysis_search`                              |
| `def download`                     | `def analysis_download`                            |
| `def systems`                      | `def server_systems`                               |
| new                                | `def submission_info`                              |
| new                                | `def submission_delete`                            |
| `def server_keyboard_layouts`      | `def server_languages_and_locales`                 |

Changes to the Command Line Interface:

| Old                              | New                                                |
| -------------                    | -------------------------------------------------- |
| `jbxapi submit`                  | Returns a submission id instead of multiple webids |
| `jbxapi info`                    | `jbxapi analysis info`                             |
| `jbxapi delete`                  | `jbxapi analysis delete`                           |
| `jbxapi list`                    | `jbxapi analysis list`                             |
| `jbxapi search`                  | `jbxapi analysis search`                           |
| `jbxapi download`                | `jbxapi analysis download`                         |
| `jbxapi report`                  | `jbxapi analysis report`                           |
| `jbxapi systems`                 | `jbxapi server systems`                            |
| new                              | `jbxapi submission info`                           |
| new                              | `jbxapi submission delete`                         |
| `jbxapi server_keyboard_layouts` | `jbxapi server languages_and_locales`              |

We recommend switching to the new submissions API and CLI.

## Breaking Change

The script prints API errors to `stdout` instead of `stderr`. The previous distinction
did not make any sense since humans easily recognize error messages and machines
can simply check the exit code of the script.

## Other changes

* We removed some old, deprecated settings.
* The script sends its version inside the user-agent header to the server.
