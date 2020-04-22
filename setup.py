import os, sys
from setuptools import setup
from setuptools.command.test import test as TestCommand

def readfile(path):
	with open(os.path.join(os.path.dirname(__file__), path)) as file:
		lines = [line.rstrip('\n') for line in file]
		return lines

class PyTest(TestCommand):
	user_options = [('pytest-args=', 'a', "Arguments to pass to py.test")]

	def initialize_options(self):
		TestCommand.initialize_options(self)
		self.pytest_args = []

	def run_tests(self):
		#import here, cause outside the eggs aren't loaded
		import pytest		
		errno = pytest.main(self.pytest_args)
		sys.exit(errno)
		
setup(
	name = "extract_icon",
	version = "0.0.2",
	author = "Fadhil Mandaga and Sturla Bae",
	author_email = "firodj@gmail.com",
	description = ("Extract icon from PE executables using pefile"),    
	keywords = "pefile, pe, icon, extraction",
	url="https://github.com/57ur14/pefile-extract-icon/",
	packages=['extract_icon'],
	install_requires=readfile('requirements.txt'),	
	tests_require=['pytest'],
	cmdclass={'test': PyTest},
	classifiers=[
		"Development Status :: 4 - Beta",
		"Environment :: Console",
		"Operating System :: OS Independent",
		"Topic :: Utilities",        
	],
)
