# Building Requirements

* flit
* build
* pytest
* Python >=3.8.7 or >=3.9.1 because earlier versions leak paths:
  https://github.com/pypa/setuptools/issues/1185#issuecomment-750900805

# Updating API docs

The API documentation must be udpated manually but the largest part can be generated automatically:

```
py -3 -c "import jbxapi, pydoc;pydoc.doc(jbxapi.JoeSandbox, output=open(sys.argv[1], 'w'))" docs/new.txt
```

# Running Tests

The tests are written with pytest:

```
py -2 -m pytest
py -3 -m pytest
```

# Building

Based on the tutorial here: https://packaging.python.org/tutorials/packaging-projects/ 

1. Build the package

```
flit build
```

3. Upload the package to PyPi:

```
flit publish
```
