import os
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

    def __call__(self, url, **kwargs):
        self.requests.append(self.Request(url=url, **kwargs))
        return self


successful_submission = {"data": {"webid": "1"}}


def test_file_submission(joe, monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    sample = io.BytesIO(b"Testdata")
    response = joe.submit_sample(sample)
    assert response == successful_submission["data"]
    assert "sample" in mock.requests[0].files


def test_file_submission_cookbook(joe, monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    sample = io.BytesIO(b"Testdata")
    cookbook = io.BytesIO(b"Testdata")
    response = joe.submit_sample(sample, cookbook)
    assert response == successful_submission["data"]
    assert "cookbook" in mock.requests[0].files
    assert "sample" in mock.requests[0].files


def test_file_submission_tuple(joe, monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    sample = io.BytesIO(b"Testdata")
    response = joe.submit_sample(("Filename", sample))
    assert response == successful_submission["data"]
    assert mock.requests[0].files["sample"] == ("Filename", sample)


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

    for i, (name, expected) in enumerate(names.items()):
        s = io.BytesIO(b"Testdata")
        s.name = name
        joe.submit_sample(s, cookbook=s)
        assert mock.requests[i * 2].files["sample"] == (expected, s)
        assert mock.requests[i * 2].files["cookbook"] == (expected, s)

        s = io.BytesIO(b"Testdata")
        joe.submit_sample((name, s), cookbook=(name, s))
        assert mock.requests[i * 2 + 1].files["sample"] == (expected, s)
        assert mock.requests[i * 2 + 1].files["cookbook"] == (expected, s)


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


def test_cookbook_submission(joe, monkeypatch):
    mock = MockedResponse(ok=True, json=successful_submission)
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    cookbook = io.BytesIO(b"Testdata")
    response = joe.submit_cookbook(cookbook)
    assert response == successful_submission["data"]
    assert "cookbook" in mock.requests[0].files
    assert "sample" not in mock.requests[0].files


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

    assert "sample" in mock.requests[0].files


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

    assert "sample" in mock.requests[0].files
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
    assert "sample" in mock.requests[0].files


def test_cli_common_params_position(monkeypatch):
    mock = MockedResponse(ok=True, json={"data": "ok"})
    monkeypatch.setattr("requests.sessions.Session.post", mock)

    # command at the start
    jbxapi.cli(["analysis", "list", "--apikey", "1234", "--apiurl", "http://example.net", "--accept-tac"])

    # command at the end
    jbxapi.cli(["--apikey", "1234", "--apiurl", "http://example.net", "--accept-tac", "analysis", "list"])
