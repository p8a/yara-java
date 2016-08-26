package com.github.plusvic.yara.embedded;

import com.github.plusvic.yara.YaraMatch;

import static com.github.plusvic.yara.Preconditions.checkArgument;

/**
 * Yara rule match
 */
public class YaraMatchImpl implements YaraMatch {
    private final YaraLibrary library;
    private final long peer;

    YaraMatchImpl(YaraLibrary library, long peer) {
        checkArgument(library != null);
        checkArgument(peer != 0);

        this.library = library;
        this.peer = peer;
    }

    /**
     * Value that was matched
     * @return
     */
    public String getValue() {
        return library.matchValue(peer);
    }

    /**
     * Offset where match was found
     * @return
     */
    public long getOffset() {
        return library.matchOffset(peer);
    }
}
