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
import shutil
import tempfile
import math

try:
    import requests
except ImportError:
    print("Please install the Python 'requests' package via pip", file=sys.stderr)
    sys.exit(1)

__version__ = "3.18.0"

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
    # password for decrypting documents like MS Office and PDFs
    'document-password': None,
    # This password will be used to decrypt archives (zip, 7z, rar etc.). Default password is "infected".
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
    # traces .Net files
    'dotnet-tracing': UnsetBool,
    # send an e-mail upon completion of the analysis
    'email-notification': UnsetBool,
    # starts the Sample with normal user privileges
    'start-as-normal-user': UnsetBool,
    # Set the system date for the analysis. Format is YYYY-MM-DD
    'system-date': None,
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
    # Use live interaction. Requires user interaction via the web UI. Default false
    'live-interaction': UnsetBool,
    # encryption password for analyses
    'encrypt-with-password': None,
    # choose the browser for URL analyses
    'browser': None,

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

    ## DEPRECATED PARAMETERS
    'office-files-password': None,
    'anti-evasion-date': UnsetBool,
    'remote-assistance': UnsetBool,
    'remote-assistance-view-only': UnsetBool,
    'static-only': UnsetBool,
}

class JoeSandbox(object):
    def __init__(self, apikey=None, apiurl=None, accept_tac=None,
                       timeout=None, verify_ssl=True, retries=3,
                       proxies=None, user_agent=None):
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
          user_agent: The user agent. Use this when you write an integration with Joe Sandbox
                      so that it is possible to track how often an integration is being used.
        """

        if apikey is None:
            apikey = os.environ.get("JBX_API_KEY", API_KEY)

        if apiurl is None:
            apiurl = os.environ.get("JBX_API_URL", API_URL)

        if accept_tac is None:
            if "JBX_ACCEPT_TAC" in os.environ:
                accept_tac = os.environ.get("JBX_ACCEPT_TAC") == "1"
            else:
                accept_tac = ACCEPT_TAC

        self.apikey = apikey
        self.apiurl = apiurl.rstrip("/")
        self.accept_tac = accept_tac
        self.timeout = timeout
        self.retries = retries

        if user_agent:
            user_agent += " (jbxapi.py {})".format(__version__)
        else:
            user_agent = "jbxapi.py {}".format(__version__)

        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.proxies = proxies
        self.session.headers.update({"User-Agent": user_agent})

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

    def submit_sample(self, sample, cookbook=None, params={},
                      _extra_params={}, _chunked_upload=True):
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

            joe = jbxapi.JoeSandbox(user_agent="My Integration")
            with open("sample.exe", "rb") as f:
                joe.submit_sample(f, params={"systems": ["w7"]})

        Example:

            import io, jbxapi

            joe = jbxapi.JoeSandbox(user_agent="My Integration")

            cookbook = io.BytesIO(b"cookbook content")
            with open("sample.exe", "rb") as f:
                joe.submit_sample(f, cookbook=cookbook)
        """
        params = copy.copy(params)
        files = {}

        self._check_user_parameters(params)

        if cookbook:
            files['cookbook'] = cookbook

        # extract sample name
        if isinstance(sample, (tuple, list)):
            filename, sample = sample
        else:  # sample is file-like object
            filename = requests.utils.guess_filename(sample) or "sample"

        retry_with_regular_upload = False
        if _chunked_upload:
            orig_pos = sample.tell()
            params["chunked-sample"] = filename

            try:
                response = self._submit(params, files, _extra_params=_extra_params)

                self._chunked_upload('/v2/submission/chunked-sample', sample, {
                    "apikey": self.apikey,
                    "submission_id": response["submission_id"],
                })
            except InvalidParameterError as e:
                # re-raise if the error is not due to unsupported chunked upload
                if "chunked-sample" not in e.message:
                    raise

                retry_with_regular_upload = True
            except _ChunkedUploadNotPossible as e:
                retry_with_regular_upload = True

        if retry_with_regular_upload:
            del params["chunked-sample"]
            sample.seek(orig_pos)

        if not _chunked_upload or retry_with_regular_upload:
            files["sample"] = (filename, sample)
            response = self._submit(params, files, _extra_params=_extra_params)

        return response

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
        
    def submit_command_line(self, command_line, params={}, _extra_params={}):
        """
        Submit a commandline for analysis.
        """
        self._check_user_parameters(params)
        params = copy.copy(params)
        params['command-line'] = command_line
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

        # rename aliases
        if 'document-password' in params:
            params['office-files-password'] = params.pop('document-password')

        # submit booleans as "0" and "1"
        for key, value in list(params.items()):
            try:
                default = submission_defaults[key]
            except KeyError:
                continue

            if default is UnsetBool or isinstance(default, bool):
                params[key] = _to_bool(value, default)

        return params

    def _submit(self, params, files=None, _extra_params={}):
        data = copy.copy(submission_defaults)
        data.update(params)
        data = self._prepare_params_for_submission(data)
        data.update(_extra_params)

        response = self._post(self.apiurl + '/v2/submission/new', data=data, files=files)
        return self._raise_or_extract(response)

    def _chunked_upload(self, url, f, params):
        try:
            file_size = self._file_size(f)
        except (IOError, OSError):
            raise _ChunkedUploadNotPossible("The file does not support chunked upload.")

        chunk_size = 10 * 1024 * 1024
        chunk_count = int(math.ceil(file_size / chunk_size))

        params = copy.copy(params)
        params.update({
            "file-size": file_size,
            "chunk-size": chunk_size,
            "chunk-count": chunk_count,
        })

        chunk_index = 1
        sent_size = 0
        response = None
        while sent_size < file_size:
            # collect next chunk
            chunk_data = io.BytesIO()
            chunk_data_len = 0
            while chunk_data_len < chunk_size:
                read_data = f.read(chunk_size - chunk_data_len)
                if read_data is None:
                    raise _ChunkedUploadNotPossible("Non-blocking files are not supported.")

                if len(read_data) <= 0:
                    break

                chunk_data.write(read_data)
                chunk_data_len += len(read_data)

            params["current-chunk-index"] = chunk_index
            params["current-chunk-size"] = chunk_data_len
            chunk_index += 1

            chunk_data.seek(0)
            response = self._post(self.apiurl + url, data=params, files={"chunk": chunk_data})
            self._raise_or_extract(response)  # raise Exception if the response is negative

            sent_size += chunk_data_len

        return response

    def _file_size(self, f):
        """
        Tries to find the size of the file-like object 'f'.
        If the file-pointer is advanced (f.tell()) it subtracts this.

        Raises ValueError if it fails to do so.
        """

        pos = f.tell()
        f.seek(0, os.SEEK_END)
        end_pos = f.tell()
        f.seek(pos, os.SEEK_SET)
        return end_pos - pos

    def submission_list(self, **kwargs):
        """
        Fetch all submissions. Returns an iterator.

        You can give the named parameter `include_shared`.

        The returned iterator can throw an exception every time `next()` is called on it.
        """

        include_shared = kwargs.get("include_shared", None)

        pagination_next = None
        while True:
            response = self._post(self.apiurl + '/v2/submission/list', data={
                "apikey": self.apikey,
                "pagination_next": pagination_next,
                "include-shared": _to_bool(include_shared),
            })

            data = self._raise_or_extract(response)
            for item in data:
                yield item

            try:
                pagination_next = response.json()["pagination"]["next"]
            except KeyError:
                break

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

    def analysis_download(self, webid, type, run=None, file=None, password=None):
        """
        Download a resource for an analysis. E.g. the full report, binaries, screenshots.
        The full list of resources can be found in our API documentation.

        When `file` is given, the return value is the filename specified by the server,
        otherwise it's a tuple of (filename, bytes).

        Parameters:
            webid:    the webid of the analysis
            type:     the report type, e.g. 'html', 'bins'
            run:      specify the run. If it is None, let Joe Sandbox pick one
            file:     a writable file-like object (When omitted, the method returns
                      the data as a bytes object.)
            password: a password for decrypting a resource (see the
                      encrypt-with-password submission option)

        Example:

            name, json_report = joe.analysis_download(123456, 'jsonfixed')

        Example:

            with open("full_report.html", "wb") as f:
                name = joe.analysis_download(123456, "html", file=f)
        """

        # when no file is specified, we create our own
        if file is None:
            _file = io.BytesIO()
        else:
            _file = file

        # password-encrypted resources have to be stored in a temp file first
        if password:
            _decrypted_file = _file
            _file = tempfile.TemporaryFile()

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

        # decrypt temporary file
        if password:
            _file.seek(0)
            self._decrypt(_file, _decrypted_file, password)
            _file.close()
            _file = _decrypted_file

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

    def joelab_machine_info(self, machine):
        """
        Show JoeLab Machine info.
        """
        response = self._post(self.apiurl + "/v2/joelab/machine/info", data={'apikey': self.apikey,
                                                                             'machine': machine})

        return self._raise_or_extract(response)

    def joelab_images_list(self, machine):
        """
        List available images.
        """
        response = self._post(self.apiurl + "/v2/joelab/machine/info", data={'apikey': self.apikey,
                                                                             'machine': machine})

        return self._raise_or_extract(response)

    def joelab_images_reset(self, machine, image=None):
        """
        Reset the disk image of a machine.
        """
        response = self._post(self.apiurl + "/v2/joelab/machine/info", data={'apikey': self.apikey,
                                                                             'machine': machine,
                                                                             'accept-tac': "1" if self.accept_tac else "0",
                                                                             'image': image})
        return self._raise_or_extract(response)

    def joelab_filesystem_upload(self, machine, file, path=None, _chunked_upload=True):
        """
        Upload a file to a Joe Lab machine.

        Parameters:
          machine       The machine id.
          file:         The file to upload. Needs to be a file-like object or a tuple in
                        the shape (filename, file-like object).
        """

        data = {
            "apikey": self.apikey,
            "accept-tac": "1" if self.accept_tac else "0",
            "machine": machine,
            "path": path,
        }

        # extract sample name
        if isinstance(file, (tuple, list)):
            filename, file = file
        else:  # sample is file-like object
            filename = requests.utils.guess_filename(file) or "file"

        retry_with_regular_upload = False
        if _chunked_upload:
            orig_pos = file.tell()
            # filename

            try:
                response = self._chunked_upload('/v2/joelab/filesystem/upload-chunked', file, data)
            except (UnknownEndpointError, _ChunkedUploadNotPossible) as e:
                retry_with_regular_upload = True
                file.seek(orig_pos)

        if not _chunked_upload or retry_with_regular_upload:
            files = {"file": (filename, file)}
            response = self._post(self.apiurl + '/v2/joelab/filesystem/upload', data=data, files=files)

        return self._raise_or_extract(response)

    def joelab_filesystem_download(self, machine, path, file):
        """
        Download a file from a Joe Lab machine.

        Parameters:
            machine:  The machine id.
            path:     The path of the file on the Joe Lab machine.
            file:     a writable file-like object

        Example:

            with open("myfile.zip", "wb") as f:
                joe.joelab_filesystem_download("w7_10", "C:\\windows32\\myfile.zip", f)
        """

        data = {'apikey': self.apikey,
                'machine': machine,
                'path': path}

        response = self._post(self.apiurl + "/v2/joelab/filesystem/download", data=data, stream=True)

        # do standard error handling when encountering an error (i.e. throw an exception)
        if not response.ok:
            self._raise_or_extract(response)
            raise RuntimeError("Unreachable because statement above should raise.")

        try:
            for chunk in response.iter_content(1024):
                file.write(chunk)
        except requests.exceptions.RequestException as e:
            raise ConnectionError(e)

    def joelab_network_info(self, machine):
        """
        Show Network info
        """
        response = self._post(self.apiurl + "/v2/joelab/network/info", data={'apikey': self.apikey,
                                                                             'machine': machine})

        return self._raise_or_extract(response)

    def joelab_network_update(self, machine, settings):
        """
        Update the network settings.
        """

        params = dict(settings)

        params["internet-enabled"] = _to_bool(params["internet-enabled"])
        params['apikey'] = self.apikey
        params['accept-tac'] = "1" if self.accept_tac else "0"
        params['machine'] = machine

        response = self._post(self.apiurl + "/v2/joelab/network/update", data=params)

        return self._raise_or_extract(response)

    def joelab_pcap_start(self, machine):
        """
        Start PCAP recording.
        """

        params = {
            'apikey': self.apikey,
            'accept-tac': "1" if self.accept_tac else "0",
            'machine': machine,
        }

        response = self._post(self.apiurl + "/v2/joelab/pcap/start", data=params)

        return self._raise_or_extract(response)

    def joelab_pcap_stop(self, machine):
        """
        Stop PCAP recording.
        """

        params = {
            'apikey': self.apikey,
            'accept-tac': "1" if self.accept_tac else "0",
            'machine': machine,
        }

        response = self._post(self.apiurl + "/v2/joelab/pcap/stop", data=params)

        return self._raise_or_extract(response)

    def joelab_pcap_download(self, machine, file):
        """
        Download the captured PCAP.

        Parameters:
            machine:  The machine id.
            file:     a writable file-like object

        Example:

            with open("dump.pcap", "wb") as f:
                joe.joelab_pcap_download("w7_10", f)
        """

        data = {'apikey': self.apikey,
                'machine': machine}

        response = self._post(self.apiurl + "/v2/joelab/pcap/download", data=data, stream=True)

        # do standard error handling when encountering an error (i.e. throw an exception)
        if not response.ok:
            self._raise_or_extract(response)
            raise RuntimeError("Unreachable because statement above should raise.")

        try:
            for chunk in response.iter_content(1024):
                file.write(chunk)
        except requests.exceptions.RequestException as e:
            raise ConnectionError(e)

    def joelab_list_exitpoints(self):
        """
        List the available internet exit points.
        """
        response = self._post(self.apiurl + "/v2/joelab/internet-exitpoints/list", data={'apikey': self.apikey})

        return self._raise_or_extract(response)

    def _decrypt(self, source, target, password):
        """
        Decrypt encrypted files downloaded from a Joe Sandbox server.
        """

        try:
            import pyzipper
        except ImportError:
            raise NotImplementedError("Decryption requires Python 3 and the pyzipper library.")

        try:
            with pyzipper.AESZipFile(source) as myzip:
                infolist = myzip.infolist()
                assert(len(infolist) == 1)

                with myzip.open(infolist[0], pwd=password) as zipmember:
                    shutil.copyfileobj(zipmember, target)
        except Exception as e:
            raise JoeException(str(e))

    def _post(self, url, data=None, **kwargs):
        """
        Wrapper around requests.post which

            (a) always inserts a timeout
            (b) converts errors to ConnectionError
            (c) re-tries a few times
        """

        # convert file names to ASCII for old urllib versions if necessary
        _urllib3_fix_filenames(kwargs)

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

class _ChunkedUploadNotPossible(JoeException):
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
                8: UnknownEndpointError,
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
class UnknownEndpointError(ApiError): pass

def _cli_bytes_from_str(text):
    """
    Python 2/3 compatibility function to ensure that what is sent on the command line
    is converted into bytes. In Python 2 this is a no-op.
    """
    if isinstance(text, bytes):
        return text
    else:
        return text.encode("utf-8", errors="surrogateescape")


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
        elif args.command_line_mode:
            print_json(joe.submit_command_line(args.sample, params=params, _extra_params=extra_params))            
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

    def submission_list(joe, args):
        print_json(list(joe.submission_list(include_shared=args.include_shared)))

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

    def account_info(joe, args):
        print_json(joe.account_info())

    def server_info(joe, args):
        print_json(joe.server_info())

    def server_lia_countries(joe, args):
        print_json(joe.server_lia_countries())

    def server_languages_and_locales(joe, args):
        print_json(joe.server_languages_and_locales())

    def analysis_report(joe, args):
        (_, report) = joe.analysis_download(args.webid, type="irjsonfixed", run=args.run, password=args.password)
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
        errors = []
        for type in args.types:
            try:
                (filename, data) = joe.analysis_download(args.webid, type=type, run=args.run, password=args.password)
            except ApiError as e:
                if not args.ignore_errors:
                    raise

                print(e.message, file=sys.stderr)
                paths[type] = None
                errors.append(e)
                continue

            path = os.path.join(args.dir, filename)
            paths[type] = os.path.abspath(path)
            try:
                with open(path, "wb") as f:
                    f.write(data)
            except Exception as e:
                # delete incomplete data in case of an exception
                os.remove(path)
                raise

        if errors and all(p is None for p in paths.values()):
            raise errors[0]

        print_json(paths)

    def analysis_search(joe, args):
        print_json(joe.analysis_search(args.searchterm))

    def server_systems(joe, args):
        print_json(joe.server_systems())

    def joelab_machine_info(joe, args):
        print_json(joe.joelab_machine_info(args.machine))

    def joelab_filesystem_upload(joe, args):
        with open(args.file, "rb") as f:
            print_json(joe.joelab_filesystem_upload(args.machine, f, args.path))

    def joelab_filesystem_download(joe, args):
        output_path = args.destination
        if os.path.isdir(output_path):
            filename = os.path.basename(args.path.replace("\\", "/"))
            output_path = os.path.join(output_path, filename)

        with open(output_path, "wb") as f:
            joe.joelab_filesystem_download(args.machine, args.path, f)

        print_json({"path": os.path.abspath(output_path)})

    def joelab_images_list(joe, args):
        print_json(joe.joelab_images_list(args.machine))

    def joelab_images_reset(joe, args):
        print_json(joe.joelab_images_reset(args.machine, args.image))

    def joelab_network_info(joe, args):
        print_json(joe.joelab_network_info(args.machine))

    def joelab_network_update(joe, args):
        print_json(joe.joelab_network_update(args.machine, {
            "internet-enabled": args.enable_internet,
            "internet-exitpoint": args.internet_exitpoint,
        }))

    def joelab_pcap_start(joe, args):
        print_json(joe.joelab_pcap_start(args.machine))

    def joelab_pcap_stop(joe, args):
        print_json(joe.joelab_pcap_stop(args.machine))

    def joelab_pcap_download(joe, args):
        output_path = args.destination
        if os.path.isdir(output_path):
            filename = "{}.pcap".format(args.machine)
            output_path = os.path.join(output_path, filename)

        with open(output_path, "wb") as f:
            joe.joelab_pcap_download(args.machine, f)

        print_json({"path": os.path.abspath(output_path)})

    def joelab_exitpoints_list(joe, args):
        print_json(joe.joelab_list_exitpoints())

    # common arguments
    common_parser = argparse.ArgumentParser(add_help=False)
    common_group = common_parser.add_argument_group("common arguments")
    common_group.add_argument('--apiurl',
        help="Api Url (You can also set the env. variable JBX_API_URL.)")
    common_group.add_argument('--apikey',
        help="Api Key (You can also set the env. variable JBX_API_KEY.)")
    common_group.add_argument('--accept-tac', action='store_true', default=None,
        help="(Joe Sandbox Cloud only): Accept the terms and conditions: "
        "https://jbxcloud.joesecurity.org/download/termsandconditions.pdf "
        "(You can also set the env. variable ACCEPT_TAC=1.)")
    common_group.add_argument('--no-check-certificate', action="store_true",
        help="Do not check the server certificate.")
    common_group.add_argument('--version', action='store_true',
            help="Show version and exit.")

    parser = argparse.ArgumentParser(description="Joe Sandbox Web API")

    # add subparsers
    subparsers = parser.add_subparsers(metavar="<command>", title="commands")
    subparsers.required = True

    # submit <filepath>
    submit_parser = subparsers.add_parser('submit', parents=[common_parser],
            usage="%(prog)s [--apiurl APIURL] [--apikey APIKEY] [--accept-tac]\n" +
                  24 * " " + "[parameters ...]\n" +
                  24 * " " + "[--url | --sample-url | --command-line | --cookbook]\n" +
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
    # command line submissions
    submission_mode_parser.add_argument('--command-line', dest="command_line_mode", action="store_true",
            help="Run the command using cmd.exe.")            
    # cookbook submission
    submission_mode_parser.add_argument('--cookbook', dest="cookbook",
            help="Use the given cookbook.")

    submit_parser.add_argument('--param', dest="extra_params", default=[], action="append", nargs=2, metavar=("NAME", "VALUE"),
            help="Specify additional parameters.")
    submit_parser.set_defaults(func=submit)

    params = submit_parser.add_argument_group('analysis parameters')

    def add_bool_param(parser, *names, **kwargs):
        dest = kwargs.pop("dest")
        help = kwargs.pop("help", None)
        assert(not kwargs)

        negative_names = []
        for name in names:
            if name.startswith("--no-"):
                negative_names.append("-" + name[4:])
            else:
                negative_names.append("--no-" + name[2:])

        parser.add_argument(*names, dest=dest, action="store_true", default=None, help=help)
        parser.add_argument(*negative_names, dest=dest, action="store_false", default=None)

    params.add_argument("--comments", dest="param-comments", metavar="TEXT",
            help="Comment for the analysis.")
    params.add_argument("--system", dest="param-systems", action="append", metavar="SYSTEM",
            help="Select systems. Can be specified multiple times.")
    params.add_argument("--analysis-time", dest="param-analysis-time", metavar="SEC",
            help="Analysis time in seconds.")
    add_bool_param(params, "--internet", dest="param-internet-access",
            help="Enable Internet Access (on by default).")
    add_bool_param(params, "--internet-simulation", dest="param-internet-simulation",
            help="Enable Internet Simulation. No Internet Access is granted.")
    add_bool_param(params, "--cache", dest="param-report-cache",
            help="Check cache for a report before analyzing the sample.")
    params.add_argument("--document-password", dest="param-document-password", metavar="PASSWORD",
            help="Password for decrypting documents like MS Office and PDFs")
    params.add_argument("--archive-password", dest="param-archive-password", metavar="PASSWORD",
            help="This password will be used to decrypt archives (zip, 7z, rar etc.). Default password is 'infected'.")
    params.add_argument("--command-line-argument", dest="param-command-line-argument", metavar="TEXT",
            help="Will start the sample with the given command-line argument. Currently only available for Windows analyzers.")
    add_bool_param(params, "--hca", dest="param-hybrid-code-analysis",
            help="Enable hybrid code analysis (on by default).")
    add_bool_param(params, "--dec", dest="param-hybrid-decompilation",
            help="Enable hybrid decompilation.")
    add_bool_param(params, "--ssl-inspection", dest="param-ssl-inspection",
            help="Inspect SSL traffic")
    add_bool_param(params, "--vbainstr", dest="param-vba-instrumentation",
            help="Enable VBA script instrumentation (on by default).")
    add_bool_param(params, "--jsinstr", dest="param-js-instrumentation",
            help="Enable JavaScript instrumentation (on by default).")
    add_bool_param(params, "--java", dest="param-java-jar-tracing",
            help="Enable Java JAR tracing (on by default).")
    add_bool_param(params, "--net", dest="param-dotnet-tracing",
            help="Enable .Net tracing.")
    add_bool_param(params, "--normal-user", dest="param-start-as-normal-user",
            help="Start sample as normal user.")
    params.add_argument("--system-date", dest="param-system-date", metavar="YYYY-MM-DD",
            help="Set the system date.")
    add_bool_param(params, "--no-unpack", "--archive-no-unpack", dest="param-archive-no-unpack",
            help="Do not unpack archive (zip, 7zip etc).")
    add_bool_param(params, "--hypervisor-based-inspection", dest="param-hypervisor-based-inspection",
            help="Enable Hypervisor based Inspection.")
    params.add_argument("--localized-internet-country", "--lia", dest="param-localized-internet-country", metavar="NAME",
            help="Country for routing internet traffic through.")
    params.add_argument("--language-and-locale", "--langloc", dest="param-language-and-locale", metavar="NAME",
            help="Language and locale to be set on Windows analyzer.")
    params.add_argument("--tag", dest="param-tags", action="append", metavar="TAG",
            help="Add tags to the analysis.")
    params.add_argument("--delete-after-days", "--delafter", type=int, dest="param-delete-after-days", metavar="DAYS",
            help="Delete analysis after X days.")
    params.add_argument("--browser", dest="param-browser", metavar="BROWSER",
            help="Browser for URL analyses.")
    add_bool_param(params, "--fast-mode", dest="param-fast-mode",
            help="Fast Mode focusses on fast analysis and detection versus deep forensic analysis.")
    add_bool_param(params, "--secondary-results", dest="param-secondary-results",
            help="Enables secondary results such as Yara rule generation, classification via Joe Sandbox Class as "
                 "well as several detail reports. "
                 "Analysis will run faster with disabled secondary results.")
    add_bool_param(params, "--apk-instrumentation", dest="param-apk-instrumentation",
            help="Perform APK DEX code instrumentation. Only applies to Android analyzer. Default on.")
    add_bool_param(params, "--amsi-unpacking", dest="param-amsi-unpacking",
            help="Perform AMSI unpacking. Only applies to Windows analyzer. Default on.")
    add_bool_param(params, "--live-interaction", dest="param-live-interaction",
            help="Use live interaction. Requires user interaction via the web UI. "
                 "Default off.")
    params.add_argument("--encrypt-with-password", "--encrypt", type=_cli_bytes_from_str,
            dest="param-encrypt-with-password", metavar="PASSWORD",
            help="Encrypt the analysis data with the given password")
    params.add_argument("--priority", dest="param-priority", type=int,
            help="Priority of submission. (Only on on-premise.)")

    # deprecated
    params.add_argument("--office-pw", dest="param-document-password", metavar="PASSWORD",
            help=argparse.SUPPRESS)
    add_bool_param(params, "--anti-evasion-date", dest="param-anti-evasion-date",
            help=argparse.SUPPRESS)
    add_bool_param(params, "--remote-assistance", dest="param-remote-assistance",
            help=argparse.SUPPRESS)

    # submission <command>
    submission_parser = subparsers.add_parser('submission',
            help="Manage submissions")
    submission_subparsers = submission_parser.add_subparsers(metavar="<submission command>", title="submission commands")
    submission_subparsers.required = True

    # submission list
    submission_list_parser = submission_subparsers.add_parser('list', parents=[common_parser],
            help="Show all submitted submissions.")
    add_bool_param(submission_list_parser, "--include-shared", dest="include_shared",
            help="Include shared submissions")
    submission_list_parser.set_defaults(func=submission_list)

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
    report_parser.add_argument('--password', type=_cli_bytes_from_str,
            help="Password for decrypting the report (see encrypt-with-password)")
    report_parser.set_defaults(func=analysis_report)

    # analysis download <id> [resource, resource, ...]
    download_parser = analysis_subparsers.add_parser('download', parents=[common_parser],
            help="Download resources of an analysis.")
    download_parser.add_argument('webid',
            help="Webid of the analysis.")
    download_parser.add_argument('--dir',
            help="Directory to store the reports in. "
                 "Defaults to <webid> in the current working directory. (Will be created.)")
    download_parser.add_argument('--run', type=int,
            help="Select the run. Omitting this option lets Joe Sandbox choose a run.")
    download_parser.add_argument('--ignore-errors', action="store_true",
            help="Report the paths as 'null' instead of aborting on the first error."
                 " In case no resource can be downloaded, an error is still raised.")
    download_parser.add_argument('--password', type=_cli_bytes_from_str,
            help="Password for decrypting the report (see encrypt-with-password)")
    download_parser.add_argument('types', nargs='*', default=['html'],
            help="Resource types to download. Consult the help for all types. "
                 "(default 'html')")
    download_parser.set_defaults(func=analysis_download)

    # account <command>
    account_parser = subparsers.add_parser('account',
            help="Query account info (Cloud Pro only)")
    account_subparsers = account_parser.add_subparsers(metavar="<command>", title="account commands")
    account_subparsers.required = True

    # account info
    account_info_parser = account_subparsers.add_parser('info', parents=[common_parser],
            help="Show information about the Joe Sandbox Cloud Pro account.")
    account_info_parser.set_defaults(func=account_info)

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

    # server languages_and_locales
    server_langloc_parser = server_subparsers.add_parser('languages_and_locales', parents=[common_parser],
            help="Show available languages and locales for Windows.")
    server_langloc_parser.set_defaults(func=server_languages_and_locales)

    # joelab <command>
    joelab_parser = subparsers.add_parser('joelab',
            help="Joe Lab Commands")
    joelab_subparsers = joelab_parser.add_subparsers(metavar="<command>", title="joelab commands")
    joelab_subparsers.required = True

    # joelab machine <command>
    joelab_machine_parser = joelab_subparsers.add_parser('machine',
            help="Machine Commands")
    joelab_machine_subparsers = joelab_machine_parser.add_subparsers(metavar="<command>", title="machine commands")
    joelab_machine_subparsers.required = True

    # joelab machine info
    joelab_machine_info_parser = joelab_machine_subparsers.add_parser('info', parents=[common_parser],
            help="Show machine info")
    joelab_machine_info_parser.add_argument("--machine", required=True, help="Joe Lab machine ID")
    joelab_machine_info_parser.set_defaults(func=joelab_machine_info)

    # joelab filesystem <command>
    joelab_filesystem_parser = joelab_subparsers.add_parser('filesystem',
            help="Filesystem Commands")
    joelab_filesystem_subparsers = joelab_filesystem_parser.add_subparsers(metavar="<command>", title="filesystem commands")
    joelab_filesystem_subparsers.required = True

    # joelab filesystem upload
    joelab_filesystem_upload_parser = joelab_filesystem_subparsers.add_parser('upload', parents=[common_parser],
            help="Upload a file to a Joe Lab machine")
    joelab_filesystem_upload_parser.add_argument("--machine", required=True, help="Machine ID")
    joelab_filesystem_upload_parser.add_argument("file", help="File to upload")
    joelab_filesystem_upload_parser.add_argument("--path", help="Path on the Joe Lab machine")
    joelab_filesystem_upload_parser.set_defaults(func=joelab_filesystem_upload)

    # joelab filesystem download
    joelab_filesystem_download_parser = joelab_filesystem_subparsers.add_parser('download', parents=[common_parser],
            help="Download a file")
    joelab_filesystem_download_parser.add_argument("--machine", required=True, help="Machine ID")
    joelab_filesystem_download_parser.add_argument("path", help="Path of file on the Joe Lab machine")
    joelab_filesystem_download_parser.add_argument("-d", "--destination", default=".", help="Destination", metavar="PATH")
    joelab_filesystem_download_parser.set_defaults(func=joelab_filesystem_download)

    # joelab images <command>
    joelab_images_parser = joelab_subparsers.add_parser('images',
            help="Images Commands")
    joelab_images_subparsers = joelab_images_parser.add_subparsers(metavar="<command>", title="images commands")
    joelab_images_subparsers.required = True

    # joelab images list
    joelab_images_list_parser = joelab_images_subparsers.add_parser('list', parents=[common_parser],
            help="List the stored images.")
    joelab_images_list_parser.add_argument("--machine", required=True, help="Joe Lab machine ID")
    joelab_images_list_parser.set_defaults(func=joelab_images_list)

    # joelab images reset
    joelab_images_reset_parser = joelab_images_subparsers.add_parser('reset', parents=[common_parser],
            help="Reset machine to an image")
    joelab_images_reset_parser.add_argument("--machine", required=True, help="Joe Lab machine ID")
    joelab_images_reset_parser.add_argument("--image", help="Image ID")
    joelab_images_reset_parser.set_defaults(func=joelab_images_reset)

    # joelab network <command>
    joelab_network_parser = joelab_subparsers.add_parser('network',
            help="Network Commands")
    joelab_network_subparsers = joelab_network_parser.add_subparsers(metavar="<command>", title="network commands")
    joelab_network_subparsers.required = True

    # joelab network info
    joelab_network_info_parser = joelab_network_subparsers.add_parser('info', parents=[common_parser],
            help="Get network info")
    joelab_network_info_parser.add_argument("--machine", required=True, help="Joe Lab machine ID")
    joelab_network_info_parser.set_defaults(func=joelab_network_info)

    # joelab network update
    joelab_network_update_parser = joelab_network_subparsers.add_parser('update', parents=[common_parser],
            help="Update the network settings of a Joe Lab Machine")
    joelab_network_update_parser.add_argument("--machine", required=True, help="Joe Lab machine ID")
    joelab_network_update_parser.add_argument("--enable-internet", dest="enable_internet", action="store_true", default=None,
            help="Enable Internet")
    joelab_network_update_parser.add_argument("--disable-internet", dest="enable_internet", action="store_false", default=None)
    joelab_network_update_parser.add_argument("--internet-exitpoint")
    joelab_network_update_parser.set_defaults(func=joelab_network_update)

    # joelab pcap <command>
    joelab_pcap_parser = joelab_subparsers.add_parser('pcap',
            help="PCAP Commands")
    joelab_pcap_subparsers = joelab_pcap_parser.add_subparsers(metavar="<command>", title="PCAP commands")
    joelab_pcap_subparsers.required = True

    # joelab pcap download
    joelab_pcap_download_parser = joelab_pcap_subparsers.add_parser('download', parents=[common_parser],
            help="Download the most recent PCAP")
    joelab_pcap_download_parser.add_argument("--machine", required=True, help="Joe Lab machine ID")
    joelab_pcap_download_parser.add_argument("-d", "--destination", default=".", help="Destination", metavar="PATH")
    joelab_pcap_download_parser.set_defaults(func=joelab_pcap_download)

    # joelab pcap start
    joelab_pcap_start_parser = joelab_pcap_subparsers.add_parser('start', parents=[common_parser],
            help="Start PCAP recodring")
    joelab_pcap_start_parser.add_argument("--machine", required=True, help="Joe Lab machine ID")
    joelab_pcap_start_parser.set_defaults(func=joelab_pcap_start)

    # joelab pcap stop
    joelab_pcap_stop_parser = joelab_pcap_subparsers.add_parser('stop', parents=[common_parser],
            help="Stop PCAP recording")
    joelab_pcap_stop_parser.add_argument("--machine", required=True, help="Joe Lab machine ID")
    joelab_pcap_stop_parser.set_defaults(func=joelab_pcap_stop)

    # joelab internet-exitpoints <command>
    joelab_exitpoints_parser = joelab_subparsers.add_parser('internet-exitpoints',
            help="Exitpoints Commands")
    joelab_exitpoints_subparsers = joelab_exitpoints_parser.add_subparsers(metavar="<command>", title="internet exitpoints commands")
    joelab_exitpoints_subparsers.required = True

    # joelab internet-exitpoints list
    joelab_exitpoints_list_parser = joelab_exitpoints_subparsers.add_parser('list', parents=[common_parser],
            help="List the available internet exitpoints")
    joelab_exitpoints_list_parser.set_defaults(func=joelab_exitpoints_list)

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
    joe = JoeSandbox(apikey=args.apikey,
                     apiurl=args.apiurl,
                     accept_tac=args.accept_tac,
                     user_agent="CLI",
                     verify_ssl=not args.no_check_certificate)
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


def _to_bool(value, default=None):
    """
    Booleans should be submitted as "0" or "1". They can also be missing.

    Returns "0", "1" or `None`
    """

    if value is None or value is UnsetBool:
        value = default

    if value is None or value is UnsetBool:
        return None
    else:
        return "1" if value else "0"


def _urllib3_fix_filenames(kwargs):
    """
    Remove non-ASCII characters from file names due to a limitation of the combination of
    urllib3 (via python-requests) and our server
    https://github.com/requests/requests/issues/2117
    Internal Ticket #3090
    """

    import urllib3

    # fixed in urllib3 1.25.2
    # https://github.com/urllib3/urllib3/pull/1492
    try:
        urllib_version = [int(p) for p in urllib3.__version__.split(".")]
    except Exception:
        print("Error parsing urllib version: " + urllib3.__version__, file=sys.stderr)
        return

    if urllib_version >= [1, 25, 2]:
        return

    if "files" in kwargs and kwargs["files"] is not None:
        acceptable_chars = "0123456789" + "abcdefghijklmnopqrstuvwxyz" + \
                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + " _-.,()[]{}"
        for param_name, fp in kwargs["files"].items():
            if isinstance(fp, (tuple, list)):
                filename, fp = fp
            else:
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


if __name__ == "__main__":
    main()
