package com.github.plusvic.yara.embedded;

import com.github.plusvic.yara.TestUtils;
import com.github.plusvic.yara.YaraCompilationCallback;
import com.github.plusvic.yara.YaraCompiler;
import com.github.plusvic.yara.YaraException;
import com.github.plusvic.yara.YaraScanner;
import net.jcip.annotations.NotThreadSafe;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * User: pba
 * Date: 6/5/15
 * Time: 6:58 PM
 */
@NotThreadSafe
public class YaraCompilerImplTest {
    private final static Logger LOGGER = Logger.getLogger(YaraCompilerImplTest.class.getName());

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

    private YaraImpl yara;

    @BeforeEach
    public void setup() {
        System.out.println("assign yara");
        this.yara = new YaraImpl();
    }

    @AfterEach
    public void teardown() throws Exception {
        this.yara.close();
    }


    @Test
    public void testCreate() throws Exception {
        try (YaraCompiler compiler = yara.createCompiler()) {
            assertNotNull(compiler);
        }
    }

    @Test
    public void testSetCallback() throws Exception {
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(new YaraCompilationCallback() {
                @Override
                public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                }
            });
        }
    }

    @Test
    public void testAddRulesContentSucceeds() throws Exception {
        YaraCompilationCallback callback = (errorLevel, fileName, lineNumber, message) -> fail();

        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(callback);
            compiler.addRulesContent(YARA_RULE_HELLO, null);
        }
    }

    @Test
    public void testAddRulesContentFails() throws Exception {
        final AtomicBoolean called = new AtomicBoolean();
        YaraCompilationCallback callback = (errorLevel, fileName, lineNumber, message) -> {
            called.set(true);
            LOGGER.log(Level.INFO, String.format("Compilation failed in %s at %d: %s", fileName, lineNumber, message));
        };

        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(callback);
            compiler.addRulesContent(YARA_RULE_FAIL, null);

            fail();
        }
        catch (YaraException e) {
        }

        assertTrue(called.get());
    }

    @Test
    public void testAddRulePackageSucceeds() throws Exception {
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };


        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(callback);
            compiler.addRulesPackage(TestUtils.getResource("rules/one-level.zip").toString(), null);
        }
    }

    @Test
    public void testAddRuleMultiLevelPackageSucceeds() throws Exception {
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };


        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(callback);
            compiler.addRulesPackage(TestUtils.getResource("rules/two-levels.zip").toString(), null);
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

        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(callback);
            compiler.addRulesPackage(TestUtils.getResource("rules/one-level.zip").toString(), null);
            compiler.addRulesPackage(TestUtils.getResource("rules/two-levels.zip").toString(), null);

            fail();
        }
        catch(YaraException e) {
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

        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(callback);
            compiler.addRulesFile(rule.toString(), null, null);
        }
    }


    @Test
    public void testAddRulesFileFails() throws Exception {
        final AtomicBoolean called = new AtomicBoolean();
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                called.set(true);
                LOGGER.log(Level.INFO, String.format("Compilation failed in %s at %d: %s",
                        fileName, lineNumber, message));
            }
        };

        Path rule = File.createTempFile(UUID.randomUUID().toString(), "yara")
                .toPath();

        Files.write(rule, YARA_RULE_FAIL.getBytes(), StandardOpenOption.WRITE);

        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(callback);
            compiler.addRulesFile(rule.toString(), rule.toString(), null);

            fail();
        }
        catch(YaraException e) {
        }

        assertTrue(called.get());
    }


    @Test
    public void testCreateScanner() throws Exception {
        YaraCompilationCallback callback = (errorLevel, fileName, lineNumber, message) -> fail();

        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(callback);
            compiler.addRulesContent(YARA_RULE_HELLO, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);
            }
        }
    }

    @Test
    @Disabled("yara asserts which stops execution")
    public void testAddRulesAfterScannerCreate() throws Exception {
        YaraCompilationCallback callback = (errorLevel, fileName, lineNumber, message) -> fail();

        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(callback);
            compiler.addRulesContent(YARA_RULE_HELLO, null);

            // Get scanner
            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);
            }

            // Subsequent add rule should fail
            try {
                compiler.addRulesContent(YARA_RULE_NOOP, null);
            }
            catch (YaraException e) {
                assertEquals(1L, e.getNativeCode());
            }
        }
    }
}
