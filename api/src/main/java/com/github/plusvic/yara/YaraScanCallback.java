package com.github.plusvic.yara;

/**
 * Yara scan callback interface
 */
public interface YaraScanCallback {
    /**
     * Called when a rule matches
     *
     * @param rule Rule that matched
     * @param dataRef
     */
    void onMatch(YaraRule rule, DataRef<Object> dataRef);
}
