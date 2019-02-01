# Development

This document contains instructions for the development of jbxapi.

## Testing

Testing is done using [`pytest`][pytest]. On windows:

    py -3 -m pytest

## Deployment

### Building the package

    py -3 .\setup.py bdist_wheel

### Upload to [PyPI][pypi]

    py -3 -m twine upload .\dist\jbxapi-2.9.4-py2.py3-none-any.whl


 [pytest]: https://pytest.org
 [pypi]: https://pypi.org
