package com.github.plusvic.yara.embedded;

/**
 * Yara module initialization callback
 */
public interface YaraModuleCallback {
    /**
     * Called when a module needs to be initialized
     * @param module
     */
    void onImport(YaraModule module);
}
