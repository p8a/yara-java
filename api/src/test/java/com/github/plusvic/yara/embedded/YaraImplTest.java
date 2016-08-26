package com.github.plusvic.yara.embedded;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import com.github.plusvic.yara.YaraCompiler;

import static org.junit.Assert.assertNotNull;

/**
 * User: pba
 * Date: 6/9/15
 * Time: 6:51 PM
 */
public class YaraImplTest {

    @BeforeClass
    public static void testInitialise() throws Exception {
        YaraImpl.initialiseApp();
    }

    @Test
    public void testCreateCompiler() throws Exception {
        try (YaraCompiler compiler = YaraImpl.newCompiler()) {
            assertNotNull(compiler);
        }
    }

    @AfterClass
    public static void testFinalise() throws Exception {
        YaraImpl.finaliseApp();
    }
}
