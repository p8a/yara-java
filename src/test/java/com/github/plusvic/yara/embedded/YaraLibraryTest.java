package com.github.plusvic.yara.embedded;

import net.jcip.annotations.NotThreadSafe;
import org.junit.Test;

import java.io.IOException;

/**
 * User: pba
 * Date: 6/5/15
 * Time: 3:01 PM
 */
@NotThreadSafe
public class YaraLibraryTest {
    @Test
    public void testCreate() {
        new YaraLibrary();
    }

    @Test
    public void testInitialize() {
        YaraLibrary library = new YaraLibrary();
        library.initialize();
    }

    @Test
    public void testFinalize() throws IOException {
        YaraLibrary library = new YaraLibrary();
        library.initialize();
    }
}
