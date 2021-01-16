[![Build Status](https://travis-ci.org/p8a/yara-java.svg)](https://travis-ci.org/p8a/yara-java)

Highlights
------------
- Does not require yara to be deployed (embeds all needed native dependencies)
- Supports two modes of operation:
  - External: yara binary extracted and executed as a child process
  - Embedded: yara jnilib runs embedded in the java process
- Rules can be loaded as strings, files or archives; for archives will recursively look for and load all yara rule files
- Matches are returned with identifier, metadata and tags
- Negate, timeout and limit supported
- Support yara 4.0.2 -- 2021/1/17


How to build 
------------  

### Get and build yara source code

Example (building from 4.0.2 version)

```
git clone https://github.com/virustotal/yara.git
cd yara
git checkout tags/v4.0.2
./bootstrap.sh
./configure --enable-shared --without-crypto CFLAGS=-fPIC
make
```

### Get and build yara-java

Example (in "yara" folder):

```
git clone https://github.com/p8a/yara-java.git
cd yara-java
mvn clean install
```

Usage and examples
------------------

See the unit tests
