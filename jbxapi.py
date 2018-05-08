#!/usr/bin/env python
# License: MIT
# Copyright Joe Security 2017

"""
jbxapi.py serves two purposes.

 (1) a light wrapper around the REST API of Joe Sandbox
 (2) a command line script to interact with Joe Sandbox

"""

from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division

import os
import sys
import io
import json
import copy
import shutil
import argparse
import time
import itertools
import random

try:
    import requests
except ImportError:
    print("Please install the Python 'requests' package via pip", file=sys.stderr)
    sys.exit(1)

__version__ = "2.5.3"

# API URL.
API_URL = "https://jbxcloud.joesecurity.org/api"
# for on-premise installations, use the following URL:
# API_URL = "http://" + webserveraddress + "/joesandbox/index.php/api"

# APIKEY, to generate goto user settings - API key
API_KEY = ""

# (for Joe Sandbox Cloud only)
# Set to True if you agree to the Terms and Conditions.
# https://jbxcloud.joesecurity.org/resources/termsandconditions.pdf
ACCEPT_TAC = False

# default submission parameters
# when specifying None, the server decides
submission_defaults = {
    # system selection, set to None for automatic selection
    # 'systems': ('w7', 'w7x64'),
    'systems': None,
    # comment for an analysis
    'comments': None,
    # maximum analysis time
    'analysis-time': None,
    # password for decrypting office files
    'office-files-password': None,
    # country for routing internet through
    'localized-internet-country': None,
    # tags
    'tags': None,
    # enable internet access during analysis
    'internet-access': None,
    # lookup samples in the report cache
    'report-cache': None,
    # hybrid code analysis
    'hybrid-code-analysis': None,
    # hybrid decompilation
    'hybrid-decompilation': None,
    # inspect ssl traffic
    'ssl-inspection': None,
    # instrumentation of vba scripts
    'vba-instrumentation': None,
    # instrumentation of javascript
    'js-instrumentation': None,
    # send an e-mail upon completion of the analysis
    'email-notification': None,
    # Only run static analysis. Disables the dynamic analysis.
    'static-only': None,

    ## JOE SANDBOX CLOUD EXCLUSIVE PARAMETERS

    # select hyper mode for a faster but less thorough analysis
    'hyper-mode': None,
    # export the report to Joe Sandbox View
    'export-to-jbxview': None,
    # lookup the reputation of URLs and domains (Requires sending URLs third-party services.)
    'url-reputation': None,

    ## ON PREMISE EXCLUSIVE PARAMETERS

    # priority of submissions
    'priority': None,

    # removed parameters
    'autosubmit-dropped': None,
    'adaptive-internet-simulation': None,
    'smart-filter': None,
}

class JoeSandbox(object):
    def __init__(self, apikey=API_KEY, apiurl=API_URL, accept_tac=ACCEPT_TAC, timeout=None, verify_ssl=True, retries=3, proxies=None):
        """
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
        """
        self.apikey = apikey
        self.apiurl = apiurl.rstrip("/")
        self.accept_tac = accept_tac
        self.timeout = timeout
        self.retries = retries

        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.proxies = proxies

    def list(self):
        """
        Fetch a list of all analyses.
        """
        response = self._post(self.apiurl + '/v2/analysis/list', data={'apikey': self.apikey})

        return self._raise_or_extract(response)

    def submit_sample(self, sample, cookbook=None, params={}, _extra_params={}):
        """
        Submit a sample and returns the associated webids for the samples.

        Parameters:
          sample:       The sample to submit. Needs to be a file-like object or a tuple in
                        the shape (filename, file-like-object).
          cookbook:     Uploads a cookbook together with the sample.
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
        """
        self._check_user_parameters(params)

        files = {'sample': sample}
        if cookbook:
            files['cookbook'] = cookbook

        return self._submit(params, files, _extra_params=_extra_params)

    def submit_sample_url(self, url, params={}, _extra_params={}):
        """
        Submit a sample at a given URL for analysis.
        """
        self._check_user_parameters(params)
        params = copy.copy(params)
        params['sample-url'] = url
        return self._submit(params, _extra_params={})

    def submit_url(self, url, params={}, _extra_params={}):
        """
        Submit a website for analysis.
        """
        self._check_user_parameters(params)
        params = copy.copy(params)
        params['url'] = url
        return self._submit(params, _extra_params=_extra_params)

    def submit_cookbook(self, cookbook, params={}, _extra_params={}):
        """
        Submit a cookbook.
        """
        self._check_user_parameters(params)
        files = {'cookbook': cookbook}
        return self._submit(params, files, _extra_params=_extra_params)

    def _submit(self, params, files=None, _extra_params={}):
        data = copy.copy(submission_defaults)
        data.update(params)

        data['apikey'] = self.apikey
        data['accept-tac'] = "1" if self.accept_tac else "0"

        # rename array parameters
        data['systems[]'] = data.pop('systems', None)
        data['tags[]'] = data.pop('tags', None)

        # submit booleans as "0" and "1"
        bool_parameters = {
            "internet-access", "report-cache", "hybrid-code-analysis", "hybrid-decompilation",
            "adaptive-internet-simulation", "ssl-inspection", "hybrid-decompilation",
            "vba-instrumentation", "email-notification", "smart-filter",
            "hyper-mode", "export-to-jbxview", "js-instrumentation",
        }
        for key, value in data.items():
            if value is not None and key in bool_parameters:
                data[key] = "1" if value else "0"

        data.update(_extra_params)

        response = self._post(self.apiurl + '/v2/analysis/submit', data=data, files=files)

        return self._raise_or_extract(response)

    def server_online(self):
        """
        Returns True if the Joe Sandbox servers are running or False if they are in maintenance mode.
        """
        response = self._post(self.apiurl + '/v2/server/online', data={'apikey': self.apikey})

        return self._raise_or_extract(response)
        
    def info(self, webid):
        """
        Show the status and most important attributes of an analysis.
        """
        response = self._post(self.apiurl + "/v2/analysis/info", data={'apikey': self.apikey, 'webid': webid})

        return self._raise_or_extract(response)
        
    def delete(self, webid):
        """
        Delete an analysis.
        """
        response = self._post(self.apiurl + "/v2/analysis/delete", data={'apikey': self.apikey, 'webid': webid})

        return self._raise_or_extract(response)

    def download(self, webid, type, run=None, file=None):
        """
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

            json_report, name = joe.download(123456, 'jsonfixed')

        Example:

            with open("full_report.html", "wb") as f:
                name = joe.download(123456, "html", file=f)
        """

        # when no file is specified, we create our own
        if file is None:
            _file = io.BytesIO()
        else:
            _file = file

        data = {
            'apikey': self.apikey,
            'webid': webid,
            'type': type,
            'run': run,
        }

        response = self._post(self.apiurl + "/v2/analysis/download", data=data, stream=True)

        try:
            filename = response.headers["Content-Disposition"].split("filename=")[1][1:-2]
        except Exception as e:
            filename = type

        # do standard error handling when encountering an error (i.e. throw an exception)
        if not response.ok:
            self._raise_or_extract(response)
            raise RuntimeError("Unreachable because statement above should raise.")

        try:
            for chunk in response.iter_content(1024):
                _file.write(chunk)
        except requests.exceptions.RequestException as e:
            raise ConnectionError(e)

        # no user file means we return the content
        if file is None:
            return (filename, _file.getvalue())
        else:
            return filename

    def search(self, query):
        """
        Lists the webids of the analyses that match the given query.

        Searches in MD5, SHA1, SHA256, filename, cookbook name, comment, url and report id.
        """
        response = self._post(self.apiurl + "/v2/analysis/search", data={'apikey': self.apikey, 'q': query})

        return self._raise_or_extract(response)

    def systems(self):
        """
        Retrieve a list of available systems.
        """
        response = self._post(self.apiurl + "/v2/server/systems", data={'apikey': self.apikey})

        return self._raise_or_extract(response)
        
    def account_info(self):
        """
        Only available on Joe Sandbox Cloud

        Show information about the account.
        """
        response = self._post(self.apiurl + "/v2/account/info", data={'apikey': self.apikey})

        return self._raise_or_extract(response)

    def server_info(self):
        """
        Query information about the server.
        """
        response = self._post(self.apiurl + "/v2/server/info", data={'apikey': self.apikey})

        return self._raise_or_extract(response)

    def server_lia_countries(self):
        """
        Show the available localized internet anonymization countries.
        """
        response = self._post(self.apiurl + "/v2/server/lia_countries", data={'apikey': self.apikey})

        return self._raise_or_extract(response)

    def _post(self, url, data=None, json=None, **kwargs):
        """
        Wrapper around requests.post which

            (a) always inserts a timeout
            (b) converts errors to ConnectionError
            (c) re-tries a few times
            (d) converts file names to ASCII
        """

        # Remove non-ASCII characters from filenames due to a limitation of the combination of
        # urllib3 (via python-requests) and our server
        # https://github.com/requests/requests/issues/2117
        # Internal Ticket #3090
        if "files" in kwargs and kwargs["files"] is not None:
            acceptable_chars = "0123456789" + "abcdefghijklmnopqrstuvwxyz" + \
                               "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + " _-.,()[]{}"
            for param_name, fp in kwargs["files"].items():
                filename = requests.utils.guess_filename(fp) or param_name

                def encode(char):
                    try:
                        if char in acceptable_chars:
                            return char
                    except UnicodeDecodeError:
                        pass
                    return "x{:02x}".format(ord(char))
                filename = "".join(encode(x) for x in filename)

                kwargs["files"][param_name] = (filename, fp)

        for i in itertools.count(1):
            try:
                return self.session.post(url, data=data, json=json, timeout=self.timeout, **kwargs)
            except requests.exceptions.Timeout as e:
                # exhausted all retries
                if i >= self.retries:
                    raise ConnectionError(e)
            except requests.exceptions.RequestException as e:
                raise ConnectionError(e)

            # exponential backoff
            max_backoff = 4 ** i / 10   # .4, 1.6, 6.4, 25.6, ...
            time.sleep(random.uniform(0, max_backoff))

    def _check_user_parameters(self, user_parameters):
        """
        Verifies that the parameter dict given by the user only contains
        known keys. This ensures that the user detects typos faster.
        """
        if not user_parameters:
            return

        # sanity check against typos
        for key in user_parameters:
            if key not in submission_defaults:
                raise ValueError("Unknown parameter {0}".format(key))

    def _raise_or_extract(self, response):
        """
        Raises an exception if the response indicates an API error.

        Otherwise returns the object at the 'data' key of the API response.
        """

        try:
            data = response.json()
        except ValueError:
            raise JoeException("The server responded with an unexpected format ({}). Is the API url correct?". format(response.status_code))

        try:
            if response.ok:
                return data['data']
            else:
                error = data['errors'][0]
                raise ApiError(error)
        except (KeyError, TypeError):
            raise JoeException("Unexpected data ({}). Is the API url correct?". format(response.status_code))

class JoeException(Exception):
    pass

class ConnectionError(JoeException):
    pass

class ApiError(JoeException):
    def __new__(cls, raw):
        # select a more specific subclass if available
        if cls is ApiError:
            subclasses = {
                2: MissingParameterError,
                3: InvalidParameterError,
                4: InvalidApiKeyError,
                5: ServerOfflineError,
                6: InternalServerError,
            }

            try:
                cls = subclasses[raw["code"]]
            except KeyError:
                pass

        return super(ApiError, cls).__new__(cls, raw["message"])
    
    def __init__(self, raw):
        super(ApiError, self).__init__(raw["message"])
        self.raw = copy.deepcopy(raw)
        self.code = raw["code"]
        self.message = raw["message"]

class MissingParameterError(ApiError): pass
class InvalidParameterError(ApiError): pass
class InvalidApiKeyError(ApiError): pass
class ServerOfflineError(ApiError): pass
class InternalServerError(ApiError): pass

def main():
    def print_json(value, file=sys.stdout):
        print(json.dumps(value, indent=4, sort_keys=True), file=file)

    def list(joe, args):
        print_json(joe.list())

    def submit(joe, args):
        params = {name[6:]: value for name, value in vars(args).items()
                                  if name.startswith("param-") and value is not None}

        extra_params = {}
        for name, value in args.extra_params:
            values = extra_params.setdefault(name, [])
            values.append(value)

        if args.url_mode:
            print_json(joe.submit_url(args.sample, params=params, _extra_params=extra_params))
        elif args.sample_url_mode:
            print_json(joe.submit_sample_url(args.sample, params=params, _extra_params=extra_params))
        else:
            with open(args.sample, "rb") as f:
                if args.cookbook is not None:
                    with open(args.cookbook, "rb") as f_cookbook:
                        print_json(joe.submit_sample(f, params=params, _extra_params=extra_params, cookbook=f_cookbook))
                else:
                    print_json(joe.submit_sample(f, params=params, _extra_params=extra_params))

    def server_online(joe, args):
        print_json(joe.server_online())

    def info(joe, args):
        print_json(joe.info(args.webid))

    def delete(joe, args):
        print_json(joe.delete(args.webid))

    def server_info(joe, args):
        print_json(joe.server_info())

    def server_lia_countries(joe, args):
        print_json(joe.server_lia_countries())

    def report(joe, args):
        (_, report) = joe.download(args.webid, type="irjsonfixed", run=args.run)
        try:
            print_json(json.loads(report))
        except json.JSONDecodeError as e:
            raise JoeException("Invalid response. Is the API url correct?")

    def download(joe, args):
        directory_created = False
        paths = {}
        if args.dir is None:
            args.dir = args.webid
            # try to create directory, raises an error if it already exists
            os.mkdir(args.dir)
            directory_created = True

        try:
            for type in args.types:
                (filename, data) = joe.download(args.webid, type=type, run=args.run)
                path = os.path.join(args.dir, filename)
                paths[type] = os.path.abspath(path)
                try:
                    with open(path, "wb") as f:
                        f.write(data)
                except Exception as e:
                    # delete incomplete data in case of an exception
                    os.remove(path)
                    raise
        except Exception as e:
            if directory_created:
                shutil.rmtree(args.dir)
            raise

        print_json(paths)

    def search(joe, args):
        print_json(joe.search(args.searchterm))

    def systems(joe, args):
        print_json(joe.systems())

    # common arguments
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument('--apiurl', default=API_URL,
        help="Api Url (You can also modify the API_URL variable inside the script.)")
    common_parser.add_argument('--apikey', default=API_KEY,
        help="Api Key (You can also modify the API_KEY variable inside the script.)")
    common_parser.add_argument('--accept-tac', action='store_true', default=ACCEPT_TAC,
        help="(Joe Sandbox Cloud only): Accept the terms and conditions: "
        "https://jbxcloud.joesecurity.org/download/termsandconditions.pdf "
        "(You can also modify the ACCEPT_TAC variable inside the script.)")
    common_parser.add_argument('--version', action='store_true',
        help="Show version and exit.")

    parser = argparse.ArgumentParser(description="Joe Sandbox Web API")

    # add subparsers
    subparsers = parser.add_subparsers(metavar="<command>", title="commands")
    subparsers.required = True

    # list
    list_parser = subparsers.add_parser('list', parents=[common_parser],
            help="Show all submitted analyses.")
    list_parser.set_defaults(func=list)

    # submit <filepath>
    submit_parser = subparsers.add_parser('submit', parents=[common_parser],
            usage="%(prog)s [--apiurl APIKEY] [--apikey APIKEY] [--accept-tac]\n" +
                  24 * " " + "[parameters ...]\n" +
                  24 * " " + "[--url | --sample-url | --cookbook COOKBOOK]\n" +
                  24 * " " + "sample",
            help="Submit a sample to Joe Sandbox.")
    submit_parser.add_argument('sample',
            help="Path or URL to the sample.")

    group = submit_parser.add_argument_group("submission mode")
    submission_mode_parser = group.add_mutually_exclusive_group(required=False)
    # url submissions
    submission_mode_parser.add_argument('--url', dest="url_mode", action="store_true",
            help="Analyse the given URL instead of a sample.")
    # sample url submissions
    submission_mode_parser.add_argument('--sample-url', dest="sample_url_mode", action="store_true",
            help="Download the sample from the given url.")
    # cookbook submission
    submission_mode_parser.add_argument('--cookbook', dest="cookbook",
            help="Use the given cookbook.")

    submit_parser.add_argument('--param', dest="extra_params", default=[], action="append", nargs=2, metavar=("NAME", "VALUE"),
            help="Specify additional parameters.")
    submit_parser.set_defaults(func=submit)

    params = submit_parser.add_argument_group('analysis parameters')

    def add_bool_param(name, dest=None, help=""):
        params.add_argument(name, dest=dest, action="store_true", default=None, help=help)
        negative_name = "--no-" + name[2:]
        params.add_argument(negative_name, dest=dest, default=None, action="store_false")

    params.add_argument("--comments", dest="param-comments", metavar="TEXT",
            help="Comment for the analysis.")
    params.add_argument("--system", dest="param-systems", action="append", metavar="SYSTEM",
            help="Select systems. Can be specified multiple times.")
    params.add_argument("--analysis-time", dest="param-analysis-time", metavar="SEC",
            help="Analysis time in seconds.")
    add_bool_param("--internet", dest="param-internet-access",
            help="Enable Internet Access.")
    add_bool_param("--cache", dest="param-report-cache",
            help="Check cache for a report before analyzing the sample.")
    params.add_argument("--office-pw", dest="param-office-files-password", metavar="PASSWORD",
            help="Password for decrypting office files.")
    add_bool_param("--hca", dest="param-hybrid-code-analysis",
            help="Enable hybrid code analysis.")
    add_bool_param("--dec", dest="param-hybrid-decompilation",
            help="Enable hybrid decompilation.")
    add_bool_param("--ais", dest="param-adaptive-internet-simulation",
            help="Enable adaptive internet simulation.")
    add_bool_param("--ssl-inspection", dest="param-ssl-inspection",
            help="Inspect SSL traffic")
    add_bool_param("--vbainstr", dest="param-vba-instrumentation",
            help="Enable VBA script instrumentation.")
    add_bool_param("--jsinstr", dest="param-js-instrumentation",
            help="Enable JavaScript instrumentation.")
    params.add_argument("--localized-internet-country", "--lia", dest="param-localized-internet-country", metavar="NAME",
            help="Country for routing internet traffic through.")
    params.add_argument("--tag", dest="param-tags", action="append", metavar="TAG",
            help="Add tags to the analysis.")

    # info <webid>
    info_parser = subparsers.add_parser('info', parents=[common_parser],
            help="Show info about an analysis.")
    info_parser.add_argument('webid',
            help="Webid of the analysis.")
    info_parser.set_defaults(func=info)

    # delete <id>
    delete_parser = subparsers.add_parser('delete', parents=[common_parser],
            help="Delete an analysis.")
    delete_parser.add_argument('webid',
            help="Webid of the analysis.")
    delete_parser.set_defaults(func=delete)

    # report <id>
    report_parser = subparsers.add_parser('report', parents=[common_parser],
            help="Print the irjsonfixed report.")
    report_parser.add_argument('webid',
            help="Webid of the analysis.")
    report_parser.add_argument('--run', type=int,
            help="Select the run.")
    report_parser.set_defaults(func=report)

    # download <id> [resource, resource, ...]
    download_parser = subparsers.add_parser('download', parents=[common_parser],
            help="Download a resource of an analysis.")
    download_parser.add_argument('webid',
            help="Webid of the analysis.")
    download_parser.add_argument('--dir',
            help="Directory to store the reports in. "
                 "Defaults to <webid> in the current working directory. (Will be created.)")
    download_parser.add_argument('--run', type=int,
            help="Select the run. Obmitting this option lets Joe Sandbox choose a run.")
    download_parser.add_argument('types', nargs='*', default=['html'],
            help="Resource types to download. "
                 "Defaults to 'html'")
    download_parser.set_defaults(func=download)

    # search <term>
    search_parser = subparsers.add_parser('search', parents=[common_parser],
            help="Search for analysis.")
    search_parser.add_argument('searchterm',
            help="Search term.")
    search_parser.set_defaults(func=search)

    # systems
    systems_parser = subparsers.add_parser('systems', parents=[common_parser],
            help="List all available systems.")
    systems_parser.set_defaults(func=systems)

    # server
    server_parser = subparsers.add_parser('server',
            help="Query server info")
    server_subparsers = server_parser.add_subparsers(metavar="<server command>", title="server commands")
    server_subparsers.required = True

    # server online
    online_parser = server_subparsers.add_parser('online', parents=[common_parser],
            help="Determine whether the Joe Sandbox servers are online or in maintenance mode.")
    online_parser.set_defaults(func=server_online)

    # server info
    server_info_parser = server_subparsers.add_parser('info', parents=[common_parser],
            help="Show information about the server.")
    server_info_parser.set_defaults(func=server_info)

    # server info
    server_info_parser = server_subparsers.add_parser('lia_countries', parents=[common_parser],
            help="Show available localized internet anonymization countries.")
    server_info_parser.set_defaults(func=server_lia_countries)
    
    # Parse common args first, this allows
    # i.e. jbxapi.py --apikey 1234 list
    # and  jbxapi.py list --apikey 1234
    common_args, remaining = common_parser.parse_known_args()

    if common_args.version:
        print(__version__)
        sys.exit()

    args = parser.parse_args(remaining)
    # overwrite args with common_args
    vars(args).update(vars(common_args))

    # run command
    joe = JoeSandbox(apikey=args.apikey, apiurl=args.apiurl, accept_tac=args.accept_tac)
    try:
        args.func(joe, args)
    except ApiError as e:
        print_json(e.raw, file=sys.stderr)
        sys.exit(e.code + 100) # api errors start from 100
    except ConnectionError as e:
        print_json({
            "code": 1,
            "message": str(e),
        }, file=sys.stderr)
        sys.exit(3)
    except (OSError, IOError) as e:
        print_json({
            "code": 1,
            "message": str(e),
        }, file=sys.stderr)
        sys.exit(4)
    except JoeException as e:
        print_json({
            "code": 1,
            "message": str(e),
        }, file=sys.stderr)
        sys.exit(5)


if __name__ == "__main__":
    main()
