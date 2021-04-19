![Joe Sandbox API v2](img/logo.png)

# API Wrapper

:warning: There have been some breaking changes in v3.0.0, please see [CHANGES.md](CHANGES.md).

The Joe Sandbox API Wrapper enables you to fully integrate Joe Sandbox into your malware analysis framework. Joe Sandbox is a deep malware analysis platform for analyzing malicious files.

You can use this wrapper with

 * [Joe Sandbox Cloud](https://www.joesecurity.org/joe-sandbox-cloud) — our Cloud hosted instance
 * [On-premise installations of Joe Sandbox](https://www.joesecurity.org/joe-security-products#on-premise) — for even more power and privacy

It is at the same time a powerful implementation of the Joe Sandbox API and also a command line tool for interacting with Joe Sandbox.

# License

The code is written in Python and licensed under MIT.

# Requirements

* Python 2.7 or higher
* Python 3.5 or higher

# Installation

## With Pip

    pip install jbxapi

:warning: On-premise installations with Joe Sandbox v25 or older should use the following version:

    pip install jbxapi==2.10.1

For upgrading `jbxapi` to a more recent version, use

    pip install --upgrade jbxapi

## Manually

1. Install the python library [`requests`](https://docs.python-requests.org/en/latest/).

        pip install requests

2. Copy `jbxapi.py` to where you need it.

# Documentation

* [Command Line Interface](docs/cli.md)
* [Python API](docs/api.md)

# Credits

* Thanks to [Pedram Amini](https://github.com/pedramamini) for a first wrapper implementation!

# Links

* [Joe Securiy LLC](https://www.joesecurity.org)
* [Joe Security Blog](https://blog.joesecurity.org)
* [Twitter @joe4security](https://twitter.com/joe4security)

