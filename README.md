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

~~~~
        // Initialise library
        YaraImpl.initialiseApp();

        //  create compiler instance
        YaraCompiler compiler = YaraImpl.newCompiler();
        try {
            // set compiler callback for exception during compilation of rules 
            compiler.setCallback((lvl, s, l, msg) -> {
                System.err.println(String.format("Failed compilation: %s, %s, %s", String.valueOf(lvl), s, msg));
            });
            
            // compile all rules from a directory recursively
            compiler.addRulesDirectory("/path/to/rules/directory", null, true);
            
            //  get instance to rules for scanning
            YaraScanner sc = compiler.createScanner();
            try {
                File subject = new File(Thread.currentThread().getContextClassLoader().getResource("libyara/NuixIntegrationTest.class").getFile());
                
                //  set call back for rule match found
                sc.setCallback((rule, ref) -> {
                    System.out.println(ref.getReference());
                });
                // scan
                sc.scan(subject);
            } finally {
                if (sc != null) {
                    try {
                        sc.close();
                    } catch (Exception e) {
                        Assert.fail(e.getMessage());
                    }
                }
            }
        } finally {
            if (compiler != null) {
                try {
                    compiler.close();
                } catch (Exception e) {
                    Assert.fail(e.getMessage());
                }
            }
        }
        
        // finalise native library
        YaraImpl.finaliseApp();
~~~~

For details, refer to unit tests


Troubleshooting
---------------
If you run into build issues with static object cannot be linked with shared (use -fPIC)
>specify --enable-shared  with configure to avoid fPIC exception on building yara-java
>Example: ``./configure --enable-shared``
For me, I had to modify Makefile for both yara and libyara and add CFLAG -fPIC, to respect the same