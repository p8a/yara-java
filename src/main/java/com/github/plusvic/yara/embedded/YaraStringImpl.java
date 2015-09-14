package com.github.plusvic.yara.embedded;

import com.github.plusvic.yara.GenericIterator;
import com.github.plusvic.yara.YaraMatch;
import com.github.plusvic.yara.YaraString;

import java.util.Iterator;

import static com.github.plusvic.yara.Preconditions.checkArgument;

/**
 * Yara rule strings
 */
public class YaraStringImpl implements YaraString {
    private final YaraLibrary library;
    private final long peer;

    YaraStringImpl(YaraLibrary library, long peer) {
        checkArgument(library != null);
        checkArgument(peer != 0);

        this.library = library;
        this.peer = peer;
    }

    /**
     * Get identifier
     *
     * @return
     */
    public String getIdentifier() {
        return library.stringIdentifier(peer);
    }

    /**
     * Get matches for the string
     *
     * @return
     */
    public Iterator<YaraMatch> getMatches() {
        return new GenericIterator<YaraMatch>() {
            private long index = library.stringMatches(peer);

            @Override
            protected YaraMatchImpl getNext() {
                if (index == 0) {
                    return null;
                }

                long last = index;
                index = library.stringMatchNext(index);

                return new YaraMatchImpl(library, last);
            }
        };
    }
}
