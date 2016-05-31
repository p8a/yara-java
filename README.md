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

Example (building from 3.4.0 version)

git clone https://github.com/plusvic/yara.git<br/>
cd yara<br/>
git checkout tags/v3.4.0<br/>
./bootstrap.sh<br/>
./configure<br/>
make<br/>

### Get and build yara-java

Example (in "yara" folder):

git clone https://github.com/papostolescu/yara-java.git<br/>
cd yara-java<br/>
mvn clean install<br/>

Usage and examples
------------------

See the unit tests
