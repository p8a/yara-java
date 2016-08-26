package com.github.plusvic.yara.external;

import com.github.plusvic.yara.*;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.Assert.*;

/**
 * User: pba
 * Date: 6/16/15
 * Time: 6:12 PM
 */
public class YaraCompilerTest {
    private final static Logger LOGGER = Logger.getLogger(YaraCompilerTest.class.getName());

    private static final String YARA_RULE_HELLO = "rule HelloWorld\n"+
            "{\n"+
            "\tstrings:\n"+
            "\t\t$a = \"Hello world\"\n"+
            "\n"+
            "\tcondition:\n"+
            "\t\t$a\n"+
            "}";

    private static final String YARA_RULE_NOOP = "rule Noop\n"+
            "{\n"+
            "\tstrings:\n"+
            "\t\t$a = \"\"\n"+
            "\n"+
            "\tcondition:\n"+
            "\t\t$a\n"+
            "}";

    private static final String YARA_RULE_FAIL = "rule HelloWorld\n"+
            "{\n"+
            "\tstrings:\n"+
            "\t\t$a = \"Hello world\"\n"+
            "\n"+
            "\tcondition:\n"+
            "\t\t$a or $b\n"+
            "}";
    public static final String RULES_DIR = "./rules";

    @Test
    public void testCreate() {
        new YaraCompilerImpl();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetNullCallback() {
         new YaraCompilerImpl().setCallback(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAddNullRule() {
        new YaraCompilerImpl().addRulesContent(null, null);
    }

    @Test
    public void testSetCallback() throws Exception {
        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(new YaraCompilationCallback() {
                @Override
                public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                }
            });
        }
    }

    @Test
    public void testAddRulesContentSucceeds() throws Exception {
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRulesContent(YARA_RULE_HELLO, null);
        }
    }

    @Test
    public void testAddRulesContentFails() throws Exception {
        final AtomicBoolean called = new AtomicBoolean();
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                called.set(true);
                LOGGER.log(Level.INFO, String.format("Compilation failed in %s at %d: %s",
                        fileName, lineNumber, message));
            }
        };

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRulesContent(YARA_RULE_FAIL, null);

            try {
                assertNotNull(compiler.createScanner());
            }
            catch (YaraException ye) {
            }
        }

        assertTrue(called.get());
    }

    @Test
    public void testAddRulesFileSucceeds() throws Exception {
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };


        Path rule = File.createTempFile(UUID.randomUUID().toString(), "yara")
                .toPath();

        Files.write(rule, YARA_RULE_HELLO.getBytes(), StandardOpenOption.WRITE);

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRulesFile(rule.toString(), null, null);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAddRulesFileFails() throws Exception {
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
            }
        };

        String rule = UUID.randomUUID().toString();

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRulesFile(rule, rule, null);
        }
    }

    @Test
    public void testAddRulePackageSucceeds() throws Exception {
        final AtomicBoolean called = new AtomicBoolean();

        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };


        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRulesPackage(TestUtils.getResource("rules/one-level.zip").toString(), null);

            // Write test file
            File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
            Files.write(Paths.get(temp.getAbsolutePath()), "Hello world".getBytes(), StandardOpenOption.WRITE);

            try (YaraScanner scanner = compiler.createScanner()) {
                scanner.setCallback(new YaraScanCallback() {
                    @Override
                    public void onMatch(YaraRule rule) {
                    }
                });
                scanner.scan(temp);
            }

            assertFalse(called.get());
        }
    }

    @Test
    public void testAddRuleMultiLevelPackageSucceeds() throws Exception {
        final AtomicBoolean called = new AtomicBoolean();

        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };


        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRulesPackage(TestUtils.getResource("rules/two-levels.zip").toString(), null);

            // Write test file
            File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
            Files.write(Paths.get(temp.getAbsolutePath()), "Hello world".getBytes(), StandardOpenOption.WRITE);

            try (YaraScanner scanner = compiler.createScanner()) {
                scanner.setCallback(new YaraScanCallback() {
                    @Override
                    public void onMatch(YaraRule rule) {
                    }
                });
                scanner.scan(temp);
            }

            assertFalse(called.get());
        }
    }

    @Test
    public void testAddRulesDirSucceeds() throws Exception {
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };
        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            Assert.assertEquals(3, compiler.addRulesDirectory(Thread.currentThread().getContextClassLoader().getResource(RULES_DIR).getPath(), null, false));
        }
    }

    @Test
    public void testAddRulesDirRecursiveSucceeds() throws Exception {
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };
        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            Assert.assertEquals(5, compiler.addRulesDirectory(Thread.currentThread().getContextClassLoader().getResource(RULES_DIR).getPath(), null, true));
        }
    }

    @Test
    public void testAddRulePackageFails() throws Exception {
        final AtomicBoolean called = new AtomicBoolean();
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                called.set(true);
                LOGGER.log(Level.INFO, String.format("Compilation failed in %s at %d: %s",
                        fileName, lineNumber, message));
            }
        };

        // Write test file
        File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
        Files.write(Paths.get(temp.getAbsolutePath()), "Hello world".getBytes(), StandardOpenOption.WRITE);

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRulesPackage(TestUtils.getResource("rules/one-level.zip").toString(), null);
            compiler.addRulesPackage(TestUtils.getResource("rules/two-levels.zip").toString(), null);

            try (YaraScanner scanner = compiler.createScanner()) {
                scanner.setCallback(new YaraScanCallback() {
                    @Override
                    public void onMatch(YaraRule rule) {
                    }
                });
                scanner.scan(temp);
            }

            assertTrue(called.get());
        }
        catch(YaraException e) {
        }

        assertTrue(called.get());
    }


    @Test
    public void testCreateScanner() throws Exception {
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRulesContent(YARA_RULE_HELLO, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);
            }
        }
    }

    @Test
    public void testAddRulesAfterScannerCreate() throws Exception {
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRulesContent(YARA_RULE_HELLO, null);

            // Get scanner
            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);
            }

            // Subsequent add rule should fail
            try {
                compiler.addRulesContent(YARA_RULE_NOOP, null);
                fail();
            }
            catch (YaraException e) {
                assertEquals(1L, e.getNativeCode());
            }
        }
    }

}
