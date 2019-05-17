#!/usr/bin/env python
# License: MIT
# Copyright Joe Security 2018

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
import argparse
import time
import itertools
import random
import errno

try:
    import requests
except ImportError:
    print("Please install the Python 'requests' package via pip", file=sys.stderr)
    sys.exit(1)

__version__ = "3.1.1"

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
UnsetBool = object()
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
    # This password will be used to decrypt archives (zip, 7z, rar etc.). Default password ist "1234".
    'archive-password': None,
    # Will start the sample with the given command-line argument. Currently only available for Windows analyzers.
    'command-line-argument': None,
    # country for routing internet through
    'localized-internet-country': None,
    # tags
    'tags': None,
    # enable internet access during analysis
    'internet-access': UnsetBool,
    # enable internet simulation during analysis
    'internet-simulation': UnsetBool,
    # lookup samples in the report cache
    'report-cache': UnsetBool,
    # hybrid code analysis
    'hybrid-code-analysis': UnsetBool,
    # hybrid decompilation
    'hybrid-decompilation': UnsetBool,
    # inspect ssl traffic
    'ssl-inspection': UnsetBool,
    # instrumentation of vba scripts
    'vba-instrumentation': UnsetBool,
    # instrumentation of javascript
    'js-instrumentation': UnsetBool,
    # traces Java JAR files
    'java-jar-tracing': UnsetBool,
    # send an e-mail upon completion of the analysis
    'email-notification': UnsetBool,
    # only run static analysis. Disables the dynamic analysis.
    'static-only': UnsetBool,
    # starts the Sample with normal user privileges
    'start-as-normal-user': UnsetBool,
    # tries to bypass time-aware samples which check the system date
    'anti-evasion-date': UnsetBool,
    # changes the locale, location, and keyboard layout of the analysis machine
    'language-and-locale': None,
    # Do not unpack archive files (zip, 7zip etc).
    'archive-no-unpack': UnsetBool,
    # Enable Hypervisor based Inspection
    "hypervisor-based-inspection": UnsetBool,
    # select fast mode for a faster but less thorough analysis
    'fast-mode': UnsetBool,
    # Enables secondary Results such as Yara rule generation, classification via Joe Sandbox Class as well as several detail reports.
    # Analysis will run faster if secondary results are not enabled.
    'secondary-results': UnsetBool,
    # Perform APK DEX code instrumentation. Only applies to Android analyzer. Default true.
    'apk-instrumentation': UnsetBool,
    # Perform AMSI unpacking. Only applies to Windows. Default true
    'amsi-unpacking': UnsetBool,
    # Use remote assistance. Only applies to Windows. Requires user interaction via the web UI. Default false
    'remote-assistance': UnsetBool,
    # Use view-only remote assistance. Only applies to Windows. Visible only through the web UI. Default false
    'remote-assistance-view-only': UnsetBool,

    ## JOE SANDBOX CLOUD EXCLUSIVE PARAMETERS

    # export the report to Joe Sandbox View
    'export-to-jbxview': UnsetBool,
    # lookup the reputation of URLs and domains (Requires sending URLs third-party services.)
    'url-reputation': UnsetBool,
    # Delete the analysis after X days
    'delete-after-days': None,

    ## ON PREMISE EXCLUSIVE PARAMETERS

    # priority of submissions
    'priority': None,
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
        self.session.headers.update({"User-Agent": "jbxapi.py {}".format(__version__)})

    def analysis_list(self):
        """
        Fetch a list of all analyses.

        Consider using `analysis_list_paged` instead.
        """
        return list(self.analysis_list_paged())

    def analysis_list_paged(self):
        """
        Fetch all analyses. Returns an iterator.

        The returned iterator can throw an exception anytime `next()` is called on it.
        """

        pagination_next = None
        while True:
            response = self._post(self.apiurl + '/v2/analysis/list', data={
                "apikey": self.apikey,
                "pagination": "1",
                "pagination_next": pagination_next,
            })

            data = self._raise_or_extract(response)
            for item in data:
                yield item

            try:
                pagination_next = response.json()["pagination"]["next"]
            except KeyError:
                break

    def submit_sample(self, sample, cookbook=None, params={}, _extra_params={}):
        """
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
        return self._submit(params, _extra_params=_extra_params)

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

    def _prepare_params_for_submission(self, params):
        params['apikey'] = self.apikey
        params['accept-tac'] = "1" if self.accept_tac else "0"

        # rename array parameters
        params['systems[]'] = params.pop('systems', None)
        params['tags[]'] = params.pop('tags', None)

        # submit booleans as "0" and "1"
        for key, value in params.items():
            try:
                default = submission_defaults[key]
            except KeyError:
                continue

            if default is True or default is False or default is UnsetBool:
                if value is None or value is UnsetBool:
                    params[key] = None
                else:
                    params[key] = "1" if value else "0"

        return params

    def _submit(self, params, files=None, _extra_params={}):
        data = copy.copy(submission_defaults)
        data.update(params)
        data = self._prepare_params_for_submission(data)
        data.update(_extra_params)

        response = self._post(self.apiurl + '/v2/submission/new', data=data, files=files)

        return self._raise_or_extract(response)

    def submission_info(self, submission_id):
        """
        Returns information about a submission including all the analysis ids.
        """
        response = self._post(self.apiurl + '/v2/submission/info', data={'apikey': self.apikey, 'submission_id': submission_id})

        return self._raise_or_extract(response)

    def submission_delete(self, submission_id):
        """
        Delete a submission.
        """
        response = self._post(self.apiurl + '/v2/submission/delete', data={'apikey': self.apikey, 'submission_id': submission_id})

        return self._raise_or_extract(response)

    def server_online(self):
        """
        Returns True if the Joe Sandbox servers are running or False if they are in maintenance mode.
        """
        response = self._post(self.apiurl + '/v2/server/online', data={'apikey': self.apikey})

        return self._raise_or_extract(response)

    def analysis_info(self, webid):
        """
        Show the status and most important attributes of an analysis.
        """
        response = self._post(self.apiurl + "/v2/analysis/info", data={'apikey': self.apikey, 'webid': webid})

        return self._raise_or_extract(response)

    def analysis_delete(self, webid):
        """
        Delete an analysis.
        """
        response = self._post(self.apiurl + "/v2/analysis/delete", data={'apikey': self.apikey, 'webid': webid})

        return self._raise_or_extract(response)

    def analysis_download(self, webid, type, run=None, file=None):
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

            json_report, name = joe.analysis_download(123456, 'jsonfixed')

        Example:

            with open("full_report.html", "wb") as f:
                name = joe.analysis_download(123456, "html", file=f)
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

    def analysis_search(self, query):
        """
        Lists the webids of the analyses that match the given query.

        Searches in MD5, SHA1, SHA256, filename, cookbook name, comment, url and report id.
        """
        response = self._post(self.apiurl + "/v2/analysis/search", data={'apikey': self.apikey, 'q': query})

        return self._raise_or_extract(response)

    def server_systems(self):
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

    def server_languages_and_locales(self):
        """
        Show the available languages and locales
        """
        response = self._post(self.apiurl + "/v2/server/languages_and_locales", data={'apikey': self.apikey})

        return self._raise_or_extract(response)

    def _post(self, url, data=None, **kwargs):
        """
        Wrapper around requests.post which

            (a) always inserts a timeout
            (b) converts errors to ConnectionError
            (c) re-tries a few times
        """

        # try the request a few times
        for i in itertools.count(1):
            try:
                return self.session.post(url, data=data, timeout=self.timeout, **kwargs)
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
                7: PermissionError,
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
class PermissionError(ApiError): pass

def cli(argv):
    def print_json(value, file=sys.stdout):
        print(json.dumps(value, indent=4, sort_keys=True), file=file)

    def analysis_list(joe, args):
        print_json(joe.analysis_list())

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
            try:
                f_cookbook = open(args.cookbook, "rb") if args.cookbook is not None else None

                def _submit_file(path):
                    with open(path, "rb") as f:
                        print_json(joe.submit_sample(f, params=params, _extra_params=extra_params, cookbook=f_cookbook))

                if os.path.isdir(args.sample):
                    for dirpath, _, filenames in os.walk(args.sample):
                        for filename in filenames:
                            _submit_file(os.path.join(dirpath, filename))
                else:
                    _submit_file(args.sample)
            finally:
                if f_cookbook is not None:
                    f_cookbook.close()

    def submission_info(joe, args):
        print_json(joe.submission_info(args.submission_id))

    def submission_delete(joe, args):
        print_json(joe.submission_delete(args.submission_id))

    def server_online(joe, args):
        print_json(joe.server_online())

    def analysis_info(joe, args):
        print_json(joe.analysis_info(args.webid))

    def analysis_delete(joe, args):
        print_json(joe.analysis_delete(args.webid))

    def server_info(joe, args):
        print_json(joe.server_info())

    def server_lia_countries(joe, args):
        print_json(joe.server_lia_countries())

    def server_languages_and_locales(joe, args):
        print_json(joe.server_languages_and_locales())

    def analysis_report(joe, args):
        (_, report) = joe.analysis_download(args.webid, type="irjsonfixed", run=args.run)
        try:
            print_json(json.loads(report))
        except json.JSONDecodeError as e:
            raise JoeException("Invalid response. Is the API url correct?")

    def analysis_download(joe, args):
        if args.dir is None:
            args.dir = args.webid
            try:
                os.mkdir(args.dir)
            except Exception as e:
                # ignore if it already exists
                if e.errno != errno.EEXIST:
                    raise

        paths = {}
        for type in args.types:
            (filename, data) = joe.analysis_download(args.webid, type=type, run=args.run)
            path = os.path.join(args.dir, filename)
            paths[type] = os.path.abspath(path)
            try:
                with open(path, "wb") as f:
                    f.write(data)
            except Exception as e:
                # delete incomplete data in case of an exception
                os.remove(path)
                raise

        print_json(paths)

    def analysis_search(joe, args):
        print_json(joe.analysis_search(args.searchterm))

    def server_systems(joe, args):
        print_json(joe.server_systems())

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

    def add_bool_param(*names, **kwargs):
        dest = kwargs.pop("dest", None)
        help = kwargs.pop("help", "")
        assert(not kwargs)

        negative_names = []
        for name in names:
            if name.startswith("--no-"):
                negative_names.append("-" + name[4:])
            else:
                negative_names.append("--no-" + name[2:])

        params.add_argument(*names, dest=dest, action="store_true", default=None, help=help)
        params.add_argument(*negative_names, dest=dest, default=None, action="store_false")

    params.add_argument("--comments", dest="param-comments", metavar="TEXT",
            help="Comment for the analysis.")
    params.add_argument("--system", dest="param-systems", action="append", metavar="SYSTEM",
            help="Select systems. Can be specified multiple times.")
    params.add_argument("--analysis-time", dest="param-analysis-time", metavar="SEC",
            help="Analysis time in seconds.")
    add_bool_param("--internet", dest="param-internet-access",
            help="Enable Internet Access (on by default).")
    add_bool_param("--internet-simulation", dest="param-internet-simulation",
            help="Enable Internet Simulation. No Internet Access is granted.")
    add_bool_param("--cache", dest="param-report-cache",
            help="Check cache for a report before analyzing the sample.")
    params.add_argument("--office-pw", dest="param-office-files-password", metavar="PASSWORD",
            help="Password for decrypting office files.")
    params.add_argument("--archive-password", dest="param-archive-password", metavar="PASSWORD",
            help="This password will be used to decrypt archives (zip, 7z, rar etc.). Default password is 'infected'.")
    params.add_argument("--command-line-argument", dest="param-command-line-argument", metavar="TEXT",
            help="Will start the sample with the given command-line argument. Currently only available for Windows analyzers.")
    add_bool_param("--hca", dest="param-hybrid-code-analysis",
            help="Enable hybrid code analysis (on by default).")
    add_bool_param("--dec", dest="param-hybrid-decompilation",
            help="Enable hybrid decompilation.")
    add_bool_param("--ssl-inspection", dest="param-ssl-inspection",
            help="Inspect SSL traffic")
    add_bool_param("--vbainstr", dest="param-vba-instrumentation",
            help="Enable VBA script instrumentation (on by default).")
    add_bool_param("--jsinstr", dest="param-js-instrumentation",
            help="Enable JavaScript instrumentation (on by default).")
    add_bool_param("--java", dest="param-java-jar-tracing",
            help="Enable Java JAR tracing (on by default).")
    add_bool_param("--normal-user", dest="param-start-as-normal-user",
            help="Start sample as normal user.")
    add_bool_param("--anti-evasion-date", dest="param-anti-evasion-date",
            help="Bypass time-aware samples.")
    add_bool_param("--no-unpack", "--archive-no-unpack", dest="param-archive-no-unpack",
            help="Do not unpack archive (zip, 7zip etc).")
    add_bool_param("--hypervisor-based-inspection", dest="param-hypervisor-based-inspection",
            help="Enable Hypervisor based Inspection.")
    params.add_argument("--localized-internet-country", "--lia", dest="param-localized-internet-country", metavar="NAME",
            help="Country for routing internet traffic through.")
    params.add_argument("--language-and-locale", "--langloc", dest="param-language-and-locale", metavar="NAME",
            help="Language and locale to be set on Windows analyzer.")
    params.add_argument("--tag", dest="param-tags", action="append", metavar="TAG",
            help="Add tags to the analysis.")
    params.add_argument("--delete-after-days", "--delafter", type=int, dest="param-delete-after-days", metavar="DAYS",
            help="Delete analysis after X days.")
    add_bool_param("--fast-mode", dest="param-fast-mode",
            help="Fast Mode focusses on fast analysis and detection versus deep forensic analysis.")
    add_bool_param("--secondary-results", dest="param-secondary-results",
            help="Enables secondary results such as Yara rule generation, classification via Joe Sandbox Class as well as several detail reports. " + \
                 "Analysis will run faster with disabled secondary results.")
    add_bool_param("--apk-instrumentation", dest="param-apk-instrumentation",
            help="Perform APK DEX code instrumentation. Only applies to Android analyzer. Default on.")
    add_bool_param("--amsi-unpacking", dest="param-amsi-unpacking",
            help="Perform AMSI unpacking. Only applies to Windows analyzer. Default on.")			
    add_bool_param("--remote-assistance", dest="param-remote-assistance",
            help="Use remote assistance. Only applies to Windows. Requires user interaction via the web UI. Default off. If enabled, disables VBA instrumentation.")
    add_bool_param("--remote-assistance-view-only", dest="param-remote-assistance-view-only",
            help="Use view-only remote assistance. Only applies to Windows. Visible only through the web UI. Default off.")

    # submission <command>
    submission_parser = subparsers.add_parser('submission',
            help="Manage submissions")
    submission_subparsers = submission_parser.add_subparsers(metavar="<submission command>", title="submission commands")
    submission_subparsers.required = True

    # submission info <submission_id>
    submission_info_parser = submission_subparsers.add_parser('info', parents=[common_parser],
            help="Show info about a submission.")
    submission_info_parser.add_argument('submission_id',
            help="Id of the submission.")
    submission_info_parser.set_defaults(func=submission_info)

    # submission delete <submission_id>
    submission_delete_parser = submission_subparsers.add_parser('delete', parents=[common_parser],
            help="Delete a submission.")
    submission_delete_parser.add_argument('submission_id',
            help="Id of the submission.")
    submission_delete_parser.set_defaults(func=submission_delete)

    # analysis <command>
    analysis_parser = subparsers.add_parser('analysis',
            help="Manage analyses")
    analysis_subparsers = analysis_parser.add_subparsers(metavar="<analysis command>", title="analysis commands")
    analysis_subparsers.required = True

    # analysis info
    analysis_info_parser = analysis_subparsers.add_parser('info', parents=[common_parser],
            help="Show information about an analysis.")
    analysis_info_parser.set_defaults(func=analysis_info)
    analysis_info_parser.add_argument('webid',
            help="Id of the analysis.")

    # analysis delete
    analysis_delete_parser = analysis_subparsers.add_parser('delete', parents=[common_parser],
            help="Delete an analysis.")
    analysis_delete_parser.set_defaults(func=analysis_delete)
    analysis_delete_parser.add_argument('webid',
            help="Id of the analysis.")

    # analysis list
    analysis_list_parser = analysis_subparsers.add_parser('list', parents=[common_parser],
            help="Show all submitted analyses.")
    analysis_list_parser.set_defaults(func=analysis_list)

    # analysis search <term>
    analysis_search_parser = analysis_subparsers.add_parser('search', parents=[common_parser],
            help="Search for analyses.")
    analysis_search_parser.add_argument('searchterm',
            help="Search term.")
    analysis_search_parser.set_defaults(func=analysis_search)

    # analysis report <id>
    report_parser = analysis_subparsers.add_parser('report', parents=[common_parser],
            help="Print the irjsonfixed report.")
    report_parser.add_argument('webid',
            help="Webid of the analysis.")
    report_parser.add_argument('--run', type=int,
            help="Select the run.")
    report_parser.set_defaults(func=analysis_report)

    # analysis download <id> [resource, resource, ...]
    download_parser = analysis_subparsers.add_parser('download', parents=[common_parser],
            help="Download a resource of an analysis.")
    download_parser.add_argument('webid',
            help="Webid of the analysis.")
    download_parser.add_argument('--dir',
            help="Directory to store the reports in. "
                 "Defaults to <webid> in the current working directory. (Will be created.)")
    download_parser.add_argument('--run', type=int,
            help="Select the run. Omitting this option lets Joe Sandbox choose a run.")
    download_parser.add_argument('types', nargs='*', default=['html'],
            help="Resource types to download. Consult the help for all types. "
                 "(default 'html')")
    download_parser.set_defaults(func=analysis_download)

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

    # server systems
    server_systems_parser = server_subparsers.add_parser('systems', parents=[common_parser],
            help="List all available systems.")
    server_systems_parser.set_defaults(func=server_systems)

    # server lia countries
    server_lia_parser = server_subparsers.add_parser('lia_countries', parents=[common_parser],
            help="Show available localized internet anonymization countries.")
    server_lia_parser.set_defaults(func=server_lia_countries)

    # server languages and locales
    server_langloc_parser = server_subparsers.add_parser('languages_and_locales', parents=[common_parser],
            help="Show available languages and locales for Windows.")
    server_langloc_parser.set_defaults(func=server_languages_and_locales)

    # Parse common args first, this allows
    # i.e. jbxapi.py --apikey 1234 list
    # and  jbxapi.py list --apikey 1234
    common_args, remaining = common_parser.parse_known_args(argv)

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
        print_json(e.raw)
        sys.exit(e.code + 100) # api errors start from 100
    except ConnectionError as e:
        print_json({
            "code": 1,
            "message": str(e),
        })
        sys.exit(3)
    except (OSError, IOError) as e:
        print_json({
            "code": 1,
            "message": str(e),
        })
        sys.exit(4)
    except JoeException as e:
        print_json({
            "code": 1,
            "message": str(e),
        })
        sys.exit(5)


def main(argv=None):
    # Workaround for a bug in Python 2.7 where sys.argv arguments are converted to ASCII and
    # non-ascii characters are replaced with '?'.
    #
    # https://bugs.python.org/issue2128
    # https://stackoverflow.com/q/846850/
    if sys.version_info[0] == 2 and sys.platform.startswith('win32'):
        def win32_unicode_argv():
            """Uses shell32.GetCommandLineArgvW to get sys.argv as a list of Unicode strings.
            """

            from ctypes import POINTER, byref, cdll, c_int, windll
            from ctypes.wintypes import LPCWSTR, LPWSTR

            GetCommandLineW = cdll.kernel32.GetCommandLineW
            GetCommandLineW.argtypes = []
            GetCommandLineW.restype = LPCWSTR

            CommandLineToArgvW = windll.shell32.CommandLineToArgvW
            CommandLineToArgvW.argtypes = [LPCWSTR, POINTER(c_int)]
            CommandLineToArgvW.restype = POINTER(LPWSTR)

            cmd = GetCommandLineW()
            argc = c_int(0)
            argv = CommandLineToArgvW(cmd, byref(argc))
            if argc.value > 0:
                # Remove Python executable and commands if present
                start = argc.value - len(sys.argv)
                return [argv[i] for i in
                        xrange(start, argc.value)]

        sys.argv = win32_unicode_argv()

    cli(argv if argv is not None else sys.argv[1:])


if __name__ == "__main__":
    main()
