package com.github.plusvic.yara;

import java.io.IOException;

/**
 * Yara wrapper
 */
public interface Yara extends AutoCloseable {
    YaraCompiler createCompiler();

    void finalise() throws IOException;
}
