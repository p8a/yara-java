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


Note
----
After you successfully added some sources you can get the compiled rules using the yr_compiler_get_rules() function. You'll get a pointer to a YR_RULES structure which can be used to scan your data as described in Scanning data. Once yr_compiler_get_rules() is invoked you can not add more sources to the compiler, but you can call yr_compiler_get_rules() multiple times. Each time this function is called it returns a pointer to the same YR_RULES structure. Notice that this behaviour is new in YARA 4.0.0, in YARA 3.X and 2.X yr_compiler_get_rules() returned a new copy the YR_RULES structure.Instances of YR_RULES must be destroyed with yr_rules_destroy().

When you call YaraCompilerImpl.createScanner() multiple times. the return YaraScanner will point to the same YR_RULES structure. so, you cann't destroy YaraScanner multiple times!!!
