from setuptools import setup

setup(name='jbxapi',
      version='1.0.0',
      description='API for Joe Sandbox',
      url='http://github.com/joesecurity/joesandboxcloudapi',
      author='Joe Security LLC',
      license='MIT',
      py_modules=['jbxapi'],
      install_requires=[
          'requests>=2.18.4,<3',
      ],
      zip_safe=False)
