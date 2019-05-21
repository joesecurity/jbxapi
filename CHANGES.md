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
| `def download`                     | `def analysis_list`                                |
| `def report`                       | `def analysis_search`                              |
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
