from pip.req import parse_requirements
from setuptools import setup
from setuptools.command.test import test as TestCommand

class PyTest(TestCommand):

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)

def read_that_file(path):
    with open(path) as open_file:
        return open_file.read()

long_description = '\n'.join((read_that_file('README.md'),
                              read_that_file('LICENSE.txt')))

version = '0.1.0'

setup(name='eisgate',
      version=version,
      description='',
      author='Kai Timofejew',
      author_email='kai@thinprintcloud.com',
      url='https://github.com/ezeep/eisgate',
      license='Proprietary License',
      packages=['eisgate'],
      include_package_data=True,
      zip_safe=True,
      tests_require=[str(req.req) for req
                     in parse_requirements('dev_requirements.txt')],
      cmdclass={'test': PyTest},
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Intended Audience :: Developers',
          'Intended Audience :: System Administrators',
          'License :: Other/Proprietary License',
          'Operating System :: OS Independent',
          'Programming Language :: Python :: 2.7',
      ]
      )