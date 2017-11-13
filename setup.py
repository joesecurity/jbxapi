from setuptools import setup

setup(name='jbxapi',
      version='2.2.1',
      description='API for Joe Sandbox',
      url='https://github.com/joesecurity/joesandboxcloudapi',
      author='Joe Security LLC',
      license='MIT',
      py_modules=['jbxapi'],
      install_requires=[
          'requests>=2.18.4,<3',
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
          'Programming Language :: Python :: 3.4',
      ])
