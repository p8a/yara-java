package com.github.plusvic.yara;

import java.io.File;
import java.util.Map;

/**
 * Yara scanner
 */
public interface YaraScanner extends AutoCloseable {
    /**
     * Set scan timeout
     */
    void setTimeout(int timeout);

    /**
     * Set scan callback
     *
     * @param cbk
     */
    void setCallback(YaraScanCallback cbk);

    /**
     * Scan file
     *
     * @param file File to scan
     */
    void scan(File file);

    /**
     * Scan file
     *
     * @param file
     * @param moduleArgs Module arguments (-x)
     */
    void scan(File file, Map<String, String> moduleArgs);
}
