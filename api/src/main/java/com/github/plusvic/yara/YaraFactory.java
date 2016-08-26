package com.github.plusvic.yara;

import com.github.plusvic.yara.embedded.YaraImpl;

/**
 * Yara factory
 */
public class YaraFactory {
    public enum Mode {
        EMBEDDED,
        EXTERNAL
    }

    public static Yara create(Mode mode) {
        switch (mode) {
            case EMBEDDED:
                return YaraImpl.instance();
            case EXTERNAL:
                return new com.github.plusvic.yara.external.YaraImpl();
            default:
                throw new UnsupportedOperationException();
        }
    }
}
