package com.github.plusvic.yara.embedded;

import com.github.plusvic.yara.*;
import net.jcip.annotations.NotThreadSafe;
import org.junit.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.easymock.EasyMock.createNiceMock;
import static org.junit.Assert.*;

/**
 * User: pba
 * Date: 6/7/15
 * Time: 6:38 PM
 */
@NotThreadSafe
public class YaraScannerImplTest {
    private static final String YARA_RULE_HELLO = "import \"pe\"\n" +
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
            "}";

    private Yara yara;

    @BeforeClass
    public static void initApp() {
        YaraImpl.initialiseApp();
    }

    @Before
    public void setup() {
        this.yara = YaraImpl.instance();
    }

    @AfterClass
    public static void teardown() throws Exception {
        YaraImpl.finaliseApp();
    }


    @Test(expected = IllegalArgumentException.class)
    public void testCreateNoRules() throws IOException {
        new YaraScannerImpl(createNiceMock(YaraLibrary.class), 0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCreateNoLibrary() {
        new YaraScannerImpl(null, 1);
    }

    @Test
    public void testCreate() {
        new YaraScannerImpl(createNiceMock(YaraLibrary.class), 1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWrongTimeout() {
        new YaraScannerImpl(createNiceMock(YaraLibrary.class), 1).setTimeout(-1);
    }

    @Test
    public void testSetCallback() throws Exception {
        //
        YaraCompilationCallback compileCallback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };

        YaraScanCallback scanCallback = new YaraScanCallback() {
            @Override
            public void onMatch(YaraRule v, DataRef<Object> dataRef) {
            }
        };

        // Create compiler and get scanner
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(YARA_RULE_HELLO, null);

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
        YaraCompilationCallback compileCallback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };

        final AtomicBoolean match = new AtomicBoolean();

        YaraScanCallback scanCallback = new YaraScanCallback() {
            @Override
            public void onMatch(YaraRule v, DataRef<Object> dataRef) {
                assertEquals("HelloWorld", v.getIdentifier());
                assertMetas(v.getMetadata());
                assertStrings(v.getStrings());
                assertTags(v.getTags());
                assertNotNull(dataRef);
                assertEquals(temp, dataRef.getReference());
                match.set(true);
            }
        };

        // Create compiler and get scanner
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(YARA_RULE_HELLO, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);

                scanner.setCallback(scanCallback);
                scanner.scan(temp);
            }
        }

        assertTrue(match.get());
    }

    @Test
    public void testScanNoMatch() throws Exception {
        // Write test file
        File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
        Files.write(Paths.get(temp.getAbsolutePath()), "Hello 1231231world".getBytes(), StandardOpenOption.WRITE);


        //
        YaraCompilationCallback compileCallback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };

        final AtomicBoolean match = new AtomicBoolean();

        YaraScanCallback scanCallback = new YaraScanCallback() {
            @Override
            public void onMatch(YaraRule v, DataRef<Object> dataRef) {
                match.set(true);
            }
        };

        // Create compiler and get scanner
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(YARA_RULE_HELLO, null);

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

        Map<String, String> args = new HashMap();
        args.put("pe", temp.getAbsolutePath());


        //
        YaraCompilationCallback compileCallback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };

        final AtomicBoolean match = new AtomicBoolean();

        YaraScanCallback scanCallback = new YaraScanCallback() {
            @Override
            public void onMatch(YaraRule v, DataRef<Object> dataRef) {
                match.set(true);
            }
        };

        // Create compiler and get scanner
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(YARA_RULE_HELLO, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);

                scanner.setCallback(scanCallback);
                scanner.scan(temp, args);
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

    private void assertTags(Iterator<String> tags) {
        assertNotNull(tags);

        assertEquals("Hello", tags.next());
        assertEquals("World", tags.next());
        assertFalse(tags.hasNext());
    }
}
