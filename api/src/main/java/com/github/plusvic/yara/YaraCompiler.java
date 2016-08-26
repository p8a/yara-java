package com.github.plusvic.yara;


import java.io.IOException;

/**
 * Yara compiler
 **/
public interface YaraCompiler extends AutoCloseable {
    /**
     * Set compilation callback
     *
     * @param cbk
     */
    void setCallback(YaraCompilationCallback cbk);

    /**
     * Add rules content
     *
     * @param content
     * @param namespace
     * @return
     */
    void addRulesContent(String content, String namespace);

    /**
     * Add rules file
     *
     * @param dirPath
     * @param recursive
     * @return
     */
    int addRulesDirectory(String dirPath, String namespace, boolean recursive);

    /**
     * Add rules file
     *
     * @param filePath
     * @param fileName
     * @param namespace
     * @return
     */
    void addRulesFile(String filePath, String fileName, String namespace);

    /**
     * Add all rules from package (zip archive)
     *
     * @param packagePath
     * @param namespace
     * @return
     */
    void addRulesPackage(String packagePath, String namespace);

    /**
     * Create scanner
     *
     * @return
     */
    YaraScanner createScanner();
}
