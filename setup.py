import re
import os

from setuptools import setup


def get_version():
    """ Extract the version number from the code. """
    here = os.path.abspath(os.path.dirname(__file__))
    jbxapi_file = os.path.join(here, "jbxapi.py")

    with open(jbxapi_file) as f:
        content = f.read()
        match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", content, re.M)

    if not match:
        raise RuntimeError("Unable to find version string.")
    return match.group(1)


setup(name='jbxapi',
      version=get_version(),
      description='API for Joe Sandbox',
      url='https://github.com/joesecurity/joesandboxcloudapi',
      author='Joe Security LLC',
      license='MIT',
      py_modules=['jbxapi'],
      install_requires=[
          'requests>=2.18.4,<3',
          # for decrypting zip files
          'pyzipper>=0.3.1;python_version>="3.5"',
      ],
      entry_points={
          'console_scripts': [
              'jbxapi=jbxapi:main'
          ],
      },
      zip_safe=False,
      keywords="security sandbox joe",
      classifiers=[
          'Development Status :: 5 - Production/Stable',

          'Intended Audience :: Developers',
          'Topic :: Security',

          'License :: OSI Approved :: MIT License',

          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7',
      ])
