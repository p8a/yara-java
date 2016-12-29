Highlights
------------
- Does not require yara to be deployed (embeds all needed native dependencies)
- Supports two modes of operation:
  - External: yara binary extracted and executed as a child process
  - Embedded: yara jnilib runs embedded in the java process
- Rules can be loaded as strings, files or archives; for archives will recursively look for and load all yara rule files
- Matches are returned with identifier, metadata and tags


How to build
------------

### Get and build yara source code
> Use 3.4.0

Follow directions from http://yara.readthedocs.io/

### Get and build yara-java
~~~~
git clone https://github.com/siddharthTyagi/yara-java.git
cd yara-java
export YARA_HOME=/path/to/compiled/yara
mvn clean install
~~~~
Usage and examples
------------------

See the unit tests


Troubleshooting
---------------
If you run into build issues with static object cannot be linked with shared (use -fPIC)
>specify --enable-shared  with configure to avoid fPIC exception on building yara-java
>Example: ``./configure --enable-shared``
For me, I had to modify Makefile for both yara and libyara and add CFLAG -fPIC, to respect the same