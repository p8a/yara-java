package com.github.plusvic.yara.external;

import com.github.plusvic.yara.*;
import net.jcip.annotations.NotThreadSafe;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * User: pba
 * Date: 6/7/15
 * Time: 6:38 PM
 */
@NotThreadSafe
public class YaraScannerImplTest {
    private static final String YARA_RULES = "import \"pe\"\n" +
            "rule HelloWorld : Hello World\n"+
            "{\n"+
            "\tmeta:\n" +
            "	my_identifier_1 = \"Some string data\"\n" +
            "	my_identifier_2 = 24\n" +
            "	my_identifier_3 = true\n" +
            "\tstrings:\n"+
            "\t\t$a = \"Hello world\"\n"+
            "\n"+
            "\tcondition:\n"+
            "\t\t$a\n"+
            "}" +
            "rule NoMatch \n"+
            "{\n"+
            "\tmeta:\n" +
            "	my_identifier_1 = \"Some string data\"\n" +
            "	my_identifier_2 = 24\n" +
            "	my_identifier_3 = true\n" +
            "\tstrings:\n"+
            "\t\t$a = \"nomatch\"\n"+
            "\n"+
            "\tcondition:\n"+
            "\t\t$a\n"+
            "}";


    @Test
    public void testCreateNoRules() {
        assertThrows(IllegalArgumentException.class, () -> new YaraScannerImpl(null));
    }

    @Test
    public void testCreate() {
        new YaraScannerImpl(Paths.get(System.getProperty("java.io.tmpdir")));
    }

    @Test
    public void testWrongTimeout() {
        YaraScannerImpl impl = new YaraScannerImpl(Paths.get(System.getProperty("java.io.tmpdir")));
        assertThrows(IllegalArgumentException.class, () -> impl.setTimeout(-1));
    }

    @Test
    public void testSetCallback() throws Exception {
        //
        YaraCompilationCallback compileCallback = (errorLevel, fileName, lineNumber, message) -> fail();

        YaraScanCallback scanCallback = v -> {};

        // Create compiler and get scanner
        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(YARA_RULES, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);

                scanner.setCallback(scanCallback);
            }
        }
    }

    @Test
    public void testScanMatch() throws Exception {
        // Write test file
        File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
        Files.write(Paths.get(temp.getAbsolutePath()), "Hello world".getBytes(), StandardOpenOption.WRITE);


        //
        YaraCompilationCallback compileCallback = (errorLevel, fileName, lineNumber, message) -> fail();

        final AtomicBoolean match = new AtomicBoolean();

        YaraScanCallback scanCallback = v -> {
            assertEquals("HelloWorld", v.getIdentifier());
            assertMetas(v.getMetadata());
            assertStrings(v.getStrings());

            match.set(true);
        };

        // Create compiler and get scanner
        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(YARA_RULES, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);

                scanner.setCallback(scanCallback);
                scanner.scan(temp);
            }
        }

        assertTrue(match.get());
    }

    @Test
    public void testScanNegateMatch() throws Exception {
        /*
            Negate and try matching on an UUID, we should have two matches
         */
        // Write test file
        File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
        Files.write(Paths.get(temp.getAbsolutePath()), UUID.randomUUID().toString().getBytes(),
                StandardOpenOption.WRITE);


        //
        YaraCompilationCallback compileCallback = (errorLevel, fileName, lineNumber, message) -> fail();

        final AtomicInteger match = new AtomicInteger();

        YaraScanCallback scanCallback = v -> {
            assertMetas(v.getMetadata());
            assertFalse(v.getStrings().hasNext());
            match.incrementAndGet();
        };

        // Create compiler and get scanner
        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(YARA_RULES, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);
                scanner.setNotSatisfiedOnly(true);

                scanner.setCallback(scanCallback);
                scanner.scan(temp);
            }
        }

        assertEquals(2, match.get());
    }

    @Test
    public void testScanNegateLimitMatch() throws Exception {
        /*
            Negate and try matching on an UUID with limit 1,
            we should have a single match
         */
        // Write test file
        File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
        Files.write(Paths.get(temp.getAbsolutePath()), UUID.randomUUID().toString().getBytes(),
                StandardOpenOption.WRITE);


        //
        YaraCompilationCallback compileCallback = (errorLevel, fileName, lineNumber, message) -> fail();

        final AtomicInteger match = new AtomicInteger();

        YaraScanCallback scanCallback = v -> {
            assertMetas(v.getMetadata());
            assertFalse(v.getStrings().hasNext());
            match.incrementAndGet();
        };

        // Create compiler and get scanner
        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(YARA_RULES, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);
                scanner.setNotSatisfiedOnly(true);
                scanner.setMaxRules(1);

                scanner.setCallback(scanCallback);
                scanner.scan(temp);
            }
        }

        assertEquals(2, match.get());
    }

    @Test
    public void testScanNoMatch() throws Exception {
        // Write test file
        File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
        Files.write(Paths.get(temp.getAbsolutePath()), "Hello 1231231world".getBytes(), StandardOpenOption.WRITE);


        //
        YaraCompilationCallback compileCallback = (errorLevel, fileName, lineNumber, message) -> fail();

        final AtomicBoolean match = new AtomicBoolean();

        YaraScanCallback scanCallback = v -> match.set(true);

        // Create compiler and get scanner
        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(YARA_RULES, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);

                scanner.setCallback(scanCallback);
                scanner.scan(temp);
            }
        }

        assertFalse(match.get());
    }

    @Test
    public void testScanModule() throws Exception {
        // Write test file
        File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
        Files.write(Paths.get(temp.getAbsolutePath()), "Hello world".getBytes(), StandardOpenOption.WRITE);

        Map<String, String> moduleArgs = new HashMap<>();
        moduleArgs.put("pe", temp.getAbsolutePath());


        //
        YaraCompilationCallback compileCallback = (errorLevel, fileName, lineNumber, message) -> fail();

        final AtomicBoolean match = new AtomicBoolean();

        YaraScanCallback scanCallback = v -> match.set(true);


        // Create compiler and get scanner
        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(YARA_RULES, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);

                scanner.setCallback(scanCallback);
                scanner.scan(temp, moduleArgs);
            }
        }

        assertTrue(match.get());
    }

    private void assertMetas(Iterator<YaraMeta> metas) {
        assertNotNull(metas);

        YaraMeta meta = metas.next();
        assertEquals(YaraMeta.Type.STRING, meta.getType());
        assertEquals("my_identifier_1", meta.getIndentifier());
        assertEquals("Some string data", meta.getString());

        meta = metas.next();
        assertEquals(YaraMeta.Type.INTEGER, meta.getType());
        assertEquals("my_identifier_2", meta.getIndentifier());
        assertEquals(24, meta.getInteger());

        meta = metas.next();
        assertEquals(YaraMeta.Type.BOOLEAN, meta.getType());
        assertEquals("my_identifier_3", meta.getIndentifier());
        assertEquals(1, meta.getInteger());

        assertFalse(metas.hasNext());
    }

    private void assertStrings(Iterator<YaraString> strings) {
        assertNotNull(strings);

        YaraString string = strings.next();

        assertEquals("$a", string.getIdentifier());

        Iterator<YaraMatch> matches = string.getMatches();
        assertTrue(matches.hasNext());

        YaraMatch match = matches.next();
        assertEquals(0, match.getOffset());
        assertEquals("Hello world", match.getValue());
        assertFalse(matches.hasNext());

        assertFalse(strings.hasNext());
    }
}
