# coding=utf-8

import os
import os.path
import copy
import io
import pytest
import tempfile
import shutil

import jbxapi


# make all network calls fail
@pytest.fixture(autouse=True)
def no_requests(monkeypatch):
    def will_fail(*args, **kwargs):
        raise RuntimeError("Disabled")
    monkeypatch.setattr("requests.sessions.Session.request", lambda: will_fail())


@pytest.fixture
def joe():
    return jbxapi.JoeSandbox()


class MockedResponse(object):
    class Request:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    def __init__(self, json=None, **kwargs):
        self._json = json
        self.__dict__.update(kwargs)
        self.requests = []

    def json(self):
        return self._json

    def __call__(self, url, data={}, files={}, **kwargs):
        self.requests.append(self.Request(url=url,
                                          data=copy.copy(data),
                                          files=copy.copy(files),
                                          **kwargs))
        return self


successful_submission = {"data": {"submission_id": "1"}}


def test_file_submission(joe, monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    sample = io.BytesIO(b"Testdata")
    response = joe.submit_sample(sample)
    assert response == successful_submission["data"]
    assert "sample" not in mock.requests[0].files
    assert "chunked-sample" in mock.requests[0].data


def test_file_submission_cookbook(joe, monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    sample = io.BytesIO(b"Testdata")
    cookbook = io.BytesIO(b"Testdata")
    response = joe.submit_sample(sample, cookbook)
    assert response == successful_submission["data"]
    assert "cookbook" in mock.requests[0].files
    assert "sample" not in mock.requests[0].files
    assert "chunked-sample" in mock.requests[0].data


def test_file_submission_tuple(joe, monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    sample = io.BytesIO(b"Testdata")
    response = joe.submit_sample(("Filename", sample))
    assert response == successful_submission["data"]
    assert mock.requests[0].data["chunked-sample"] == "Filename"


def test_chunked_upload_fallback(joe, monkeypatch):
    """ Fall back to non-chunked upload if the server does not
        support it. """

    error_response = {
        "errors": [{
            "code": 3,
            "message": "Unknown parameter chunked-sample.",
        }],
    }

    mock = MockedResponse(ok=False, json=error_response)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    sample = io.BytesIO(b"Test Content")
    try:
        joe.submit_sample(sample)
    except jbxapi.InvalidParameterError:
        """ This exception is expected since the fallback-request
            also gets an error response. """
        pass

    assert "chunked-sample" in mock.requests[0].data
    assert "sample" not in mock.requests[0].files

    assert "chunked-sample" not in mock.requests[1].data
    assert "sample" in mock.requests[1].files


def test_strange_file_names(joe, monkeypatch):
    names = {
        "Sample": "Sample",
        "\xc3\xb6": "xc3xb6",
        "|": "x7c",
    }

    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)
    # only necessary for urllib3 < 1.25.2
    monkeypatch.setattr("urllib3.__version__", "1.25.1")

    for name, expected in names.items():
        s = io.BytesIO(b"Testdata")
        s.name = name
        del mock.requests[:]
        joe.submit_sample(s, cookbook=s, _chunked_upload=False)
        assert mock.requests[0].files["sample"] == (expected, s)
        assert mock.requests[0].files["cookbook"] == (expected, s)

        del mock.requests[:]
        s = io.BytesIO(b"Testdata")
        joe.submit_sample((name, s), cookbook=(name, s), _chunked_upload=False)
        assert mock.requests[0].files["sample"] == (expected, s)
        assert mock.requests[0].files["cookbook"] == (expected, s)


def test_url_submission(joe, monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    response = joe.submit_url("https://example.net")
    assert response == successful_submission["data"]
    assert "url" in mock.requests[0].data
    assert mock.requests[0].files is None


def test_sample_url_submission(joe, monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    response = joe.submit_sample_url("https://example.net/sample")
    assert response == successful_submission["data"]
    assert "sample-url" in mock.requests[0].data
    assert mock.requests[0].files is None

def test_command_line_submission(joe, monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    response = joe.submit_command_line("ipconfig")
    assert response == successful_submission["data"]
    assert "command-line" in mock.requests[0].data
    assert mock.requests[0].files is None

def test_cookbook_submission(joe, monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    cookbook = io.BytesIO(b"Testdata")
    response = joe.submit_cookbook(cookbook)
    assert response == successful_submission["data"]
    assert "cookbook" in mock.requests[0].files
    assert "sample" not in mock.requests[0].files
    assert "chunked-sample" not in mock.requests[0].files


def test_boolean_parameters(joe, monkeypatch):
    tests = {
        # true values
        "truish": "1",
        True: "1",

        # false values
        False: "0",
        "": "0",

        # no preference
        None: None,

        # no preference (bool)
        jbxapi.UnsetBool: None,
    }

    for value, expected in tests.items():
        mock = MockedResponse(ok=True, json=successful_submission)
        monkeypatch.setattr("requests.sessions.Session.post", mock)

        joe.submit_url("https://example.net", params={"internet-access": value})
        assert mock.requests[0].data["internet-access"] == expected


def test_array_parameters(joe, monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    joe.submit_url("https://example.net", params={"systems": ["w7"], "tags": ["mytag"]})

    assert mock.requests[0].data["systems[]"] == ["w7"]
    assert "systems" not in mock.requests[0].data

    assert mock.requests[0].data["tags[]"] == ["mytag"]
    assert "tags" not in mock.requests[0].data


def test_array_parameters_single_value(joe, monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    joe.submit_url("https://example.net", params={"systems": "w7", "tags": "mytag"})

    assert mock.requests[0].data["systems[]"] == "w7"
    assert "systems" not in mock.requests[0].data

    assert mock.requests[0].data["tags[]"] == "mytag"
    assert "tags" not in mock.requests[0].data


def test_user_agent():
    joe = jbxapi.JoeSandbox()
    assert "jbxapi.py" in joe.session.headers["User-Agent"]
    assert jbxapi.__version__ in joe.session.headers["User-Agent"]

    joe = jbxapi.JoeSandbox(user_agent="My Integration")
    assert "jbxapi.py" in joe.session.headers["User-Agent"]
    assert "My Integration" in joe.session.headers["User-Agent"]
    assert jbxapi.__version__ in joe.session.headers["User-Agent"]


def test_api_key_input_methods(monkeypatch):
    monkeypatch.setattr("jbxapi.API_KEY", "from_script")
    joe = jbxapi.JoeSandbox()
    assert joe.apikey == "from_script"

    monkeypatch.setenv("JBX_API_KEY", "from_env")
    joe = jbxapi.JoeSandbox()
    assert joe.apikey == "from_env"

    joe = jbxapi.JoeSandbox(apikey="from_arg")
    assert joe.apikey == "from_arg"


def test_api_url_input_methods(monkeypatch):
    monkeypatch.setattr("jbxapi.API_URL", "from_script")
    joe = jbxapi.JoeSandbox()
    assert joe.apiurl == "from_script"

    monkeypatch.setenv("JBX_API_URL", "from_env")
    joe = jbxapi.JoeSandbox()
    assert joe.apiurl == "from_env"

    joe = jbxapi.JoeSandbox(apiurl="from_arg")
    assert joe.apiurl == "from_arg"


def test_accept_tac_input_methods(monkeypatch):
    # The test alternates between True and False to test the
    # order of precedence of the options

    monkeypatch.setattr("jbxapi.ACCEPT_TAC", True)
    joe = jbxapi.JoeSandbox()
    assert joe.accept_tac is True

    monkeypatch.setenv("JBX_ACCEPT_TAC", "0")
    joe = jbxapi.JoeSandbox()
    assert joe.accept_tac is False

    monkeypatch.setenv("JBX_ACCEPT_TAC", "1")
    joe = jbxapi.JoeSandbox()
    assert joe.accept_tac is True

    joe = jbxapi.JoeSandbox(accept_tac=False)
    assert joe.accept_tac is False


def test_renames_document_password(joe, monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    joe.submit_sample_url("https://example.net", params={"document-password": "password"})

    assert mock.requests[0].data["office-files-password"] == "password"
    assert "document-password" not in mock.requests[0].data


def test_file_size_test(joe):
    # file
    with tempfile.NamedTemporaryFile() as f:
        f.write(b'Some data')

        f.seek(0)
        assert joe._file_size(f) == 9

        f.seek(4)
        assert joe._file_size(f) == 5

    # io.BytesIO
    buf = io.BytesIO(b"Some data")
    buf.seek(0)
    assert joe._file_size(buf) == 9

    buf.seek(4)
    assert joe._file_size(buf) == 5


def test_chunking(joe, monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    with tempfile.NamedTemporaryFile() as f:
        for i in range(0, 59):
            f.write(1024 * 1024 * b'b')  # write 1MB
        f.seek(0)

        joe.submit_sample(f)

        assert len(mock.requests) == 7

        # test initial request
        assert "sample" not in mock.requests[0].data
        assert mock.requests[0].data["chunked-sample"] == os.path.basename(f.name)
        assert mock.requests[0].url == "https://jbxcloud.joesecurity.org/api/v2/submission/new"

        # test first chunk
        assert mock.requests[1].data == {
            "apikey": "",
            "submission_id": "1",
            "chunk-size": 10485760,
            "file-size": 61865984,
            "chunk-count": 6,
            "current-chunk-index": 1,
            "current-chunk-size": 10485760,
        }
        assert mock.requests[1].url == "https://jbxcloud.joesecurity.org/api/v2/submission/chunked-sample"
        assert type(mock.requests[1].data["chunk-count"]) == int
        assert type(mock.requests[1].data["current-chunk-size"]) == int

        # test last chunk
        assert mock.requests[6].url == "https://jbxcloud.joesecurity.org/api/v2/submission/chunked-sample"
        assert mock.requests[6].data == {
            "apikey": "",
            "submission_id": "1",
            "chunk-size": 10485760,
            "file-size": 61865984,
            "chunk-count": 6,
            "current-chunk-index": 6,
            "current-chunk-size": 9437184,
        }
        assert type(mock.requests[6].data["chunk-count"]) == int
        assert type(mock.requests[6].data["current-chunk-size"]) == int


def test_joelab_filesystem_upload(joe, monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    with tempfile.NamedTemporaryFile() as f:
        for i in range(0, 59):
            f.write(1024 * 1024 * b'b')  # write 1MB
        f.seek(0)

        joe.joelab_filesystem_upload("machine", f)

    assert mock.requests[0].url == "https://jbxcloud.joesecurity.org/api/v2/joelab/filesystem/upload-chunked"

# CLI tests
def test_cli_submit_file(monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    with tempfile.NamedTemporaryFile(delete=False) as temp:
        temp.write(b'Some data')

    try:
        jbxapi.cli(["submit", temp.name])
    finally:
        os.remove(temp.name)

    assert "chunked-sample" in mock.requests[0].data


def test_cli_submit_dir(monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    sample_dir = tempfile.mkdtemp()
    with tempfile.NamedTemporaryFile(dir=sample_dir, delete=False) as temp:
        temp.write(b'Some data')

    with tempfile.NamedTemporaryFile(dir=sample_dir, delete=False) as temp:
        temp.write(b'Some other data')

    try:
        jbxapi.cli(["submit", sample_dir])
    finally:
        shutil.rmtree(sample_dir)

    assert "chunked-sample" in mock.requests[0].data
    print(mock.requests[0].files)


def test_cli_submit_url(monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    jbxapi.cli(["submit", "--url", "https://example.net"])

    assert mock.requests[0].data["url"] == "https://example.net"


def test_cli_submit_sample_url(monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    jbxapi.cli(["submit", "--sample-url", "https://example.net/sample"])

    assert mock.requests[0].data["sample-url"] == "https://example.net/sample"


def test_cli_submit_sample_with_cookbook(monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    with tempfile.NamedTemporaryFile(delete=False) as temp1:
        temp1.write(b'Some data')

    with tempfile.NamedTemporaryFile(delete=False) as temp2:
        temp2.write(b'Some data')

    jbxapi.cli(["submit", "--cookbook", temp1.name, temp2.name])

    assert "cookbook" in mock.requests[0].files
    assert "chunked-sample" in mock.requests[0].data


def test_cli_common_params_position(monkeypatch):
    mock = MockedResponse(ok=True, json={"data": "ok"})
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    # command at the start
    jbxapi.cli(["analysis", "list", "--apikey", "1234", "--apiurl", "http://example.net", "--accept-tac"])

    # command at the end
    jbxapi.cli(["--apikey", "1234", "--apiurl", "http://example.net", "--accept-tac", "analysis", "list"])


def test_cli_password(monkeypatch):
    assert jbxapi._cli_bytes_from_str("test") == b"test"

    # utf-8
    assert jbxapi._cli_bytes_from_str("ö") == b"\xc3\xb6"

def test_cli_api_key_input_methods(monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    monkeypatch.setattr("jbxapi.API_KEY", "from_script")
    jbxapi.cli(["submit", "--url", "https://example.net"])
    assert mock.requests[-1].data["apikey"] == "from_script"

    monkeypatch.setenv("JBX_API_KEY", "from_env")
    jbxapi.cli(["submit", "--url", "https://example.net"])
    assert mock.requests[-1].data["apikey"] == "from_env"

    jbxapi.cli(["submit", "--url", "https://example.net", "--apikey", "from_arg"])
    assert mock.requests[-1].data["apikey"] == "from_arg"


def test_cli_api_url_input_methods(monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    monkeypatch.setattr("jbxapi.API_URL", "from_script")
    jbxapi.cli(["submit", "--url", "https://example.net"])
    assert mock.requests[-1].url.startswith("from_script")

    monkeypatch.setenv("JBX_API_URL", "from_env")
    jbxapi.cli(["submit", "--url", "https://example.net"])
    assert mock.requests[-1].url.startswith("from_env")

    jbxapi.cli(["submit", "--url", "https://example.net", "--apiurl", "from_arg"])
    assert mock.requests[-1].url.startswith("from_arg")


def test_cli_accept_tac_input_methods(monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    # The test alternates between True and False to test the
    # order of precedence of the options

    monkeypatch.setattr("jbxapi.ACCEPT_TAC", True)
    jbxapi.cli(["submit", "--url", "https://example.net"])
    assert mock.requests[-1].data["accept-tac"] == "1"

    monkeypatch.setenv("JBX_ACCEPT_TAC", "0")
    jbxapi.cli(["submit", "--url", "https://example.net"])
    assert mock.requests[-1].data["accept-tac"] == "0"

    monkeypatch.setenv("JBX_ACCEPT_TAC", "1")
    jbxapi.cli(["submit", "--url", "https://example.net"])
    assert mock.requests[-1].data["accept-tac"] == "1"

    # disable it again
    monkeypatch.setenv("JBX_ACCEPT_TAC", "0")

    jbxapi.cli(["submit", "--url", "https://example.net", "--accept-tac"])
    assert mock.requests[-1].data["accept-tac"] == "1"


def test_cli_no_check_certificate(monkeypatch):
    response = MockedResponse(ok=True, json=successful_submission)

    def request(self, *args, **kwargs):
        # self is the session
        response.verify_ssl = self.verify
        return MockedResponse(ok=True, json=successful_submission)

    monkeypatch.setattr("requests.sessions.Session.request", request)
    jbxapi.cli(["submit", "--url", "https://example.net"])

    assert response.verify_ssl is True

    jbxapi.cli(["submit", "--url", "https://example.net", "--no-check-certificate"])

    assert response.verify_ssl is False

# helpers test

def test_to_bool():
    assert jbxapi._to_bool(True) == "1"
    assert jbxapi._to_bool(False) == "0"

    assert jbxapi._to_bool("trueish") == "1"
    assert jbxapi._to_bool("") == "0"

    assert jbxapi._to_bool(None) is None

    assert jbxapi._to_bool(None, None) is None
    assert jbxapi._to_bool(None, True) == "1"
    assert jbxapi._to_bool(None, False) == "0"

    assert jbxapi._to_bool(jbxapi.UnsetBool, None) is None
    assert jbxapi._to_bool(jbxapi.UnsetBool, True) == "1"
    assert jbxapi._to_bool(jbxapi.UnsetBool, False) == "0"

    assert jbxapi._to_bool(None, jbxapi.UnsetBool) is None
