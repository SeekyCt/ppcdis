
import os
import sys
import subprocess
from setuptools import setup

from setuptools.command.develop import develop
from setuptools.command.install import install
from distutils.spawn import find_executable

# protobuf logic largely taken from here http://web.mit.edu/andersk/src/protobuf-2.5.0/python/setup.py
# Find the Protocol Compiler.
if 'PROTOC' in os.environ and os.path.exists(os.environ['PROTOC']):
  protoc = os.environ['PROTOC']
else:
  protoc = find_executable("protoc")


here = os.path.dirname(__file__) or '.'

proto_dir = os.path.join(here, "proto")

class PpcdisDevelopCommand(develop):
    def run(self):
        compile_proto()
        develop.run(self)

class PpcdisInstallCommand(install):
    def run(self):
        compile_proto()
        install.run(self)


def generate_proto(source):
    """Invokes the Protocol Compiler to generate a _pb2.py from the given
    .proto file.  Does nothing if the output already exists and is newer than
    the input."""

    output = source.replace(".proto", "_pb2.py")

    if (not os.path.exists(output) or
        (os.path.exists(source) and
        os.path.getmtime(source) > os.path.getmtime(output))):
        print(f"Generating {output}...")

    if not os.path.exists(source):
        sys.stderr.write("Can't find required file: %s\n" % source)
        sys.exit(-1)

    if protoc == None:
        sys.stderr.write("protoc is not installed nor found in ../src.  Please compile it "
          "or install the binary package.\n")
        sys.exit(-1)

    python_out = os.path.join(here, "ppcdis")

    protoc_command = [ protoc, "-I" + proto_dir, "--python_out=" + python_out, source ]
    if subprocess.call(protoc_command) != 0:
        sys.exit(-1)


def compile_proto():
    # Generate necessary .proto file if it doesn't exist.
    proto_files = ["labelinfo.proto", "relocinfo.proto"]

    for proto_file in proto_files:
        generate_proto(os.path.join(proto_dir, proto_file))


setup(
    name='ppcdis',
    author="Seeky",
    classifiers=[
        "License :: OSI Approved :: MIT License"
    ],
    packages=["ppcdis"],
    scripts=["analyser.py", "disassembler.py"],
    python_requires=">=3.8",
    install_requires=[
        'colorama',
        'capstone',
        'pyelftools',
        'pylibyaml',
        'protobuf==4.21.0',
        'PyYAML'
    ],
    cmdclass=dict(
        install=PpcdisInstallCommand,
        develop=PpcdisDevelopCommand),
)
