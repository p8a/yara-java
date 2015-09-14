package com.github.plusvic.yara.embedded;

import com.github.plusvic.yara.*;

import java.util.Iterator;

import static com.github.plusvic.yara.Preconditions.checkArgument;

/**
 * Yara rule
 */
public class YaraRuleImpl implements YaraRule {
    private final YaraLibrary library;
    private final long peer;

    YaraRuleImpl(YaraLibrary library, long peer) {
        checkArgument(library != null);
        checkArgument(peer != 0);

        this.library = library;
        this.peer = peer;
    }

    /**
     * Rule identifier
     *
     * @return
     */
    public String getIdentifier() {
        return library.ruleIdentifier(peer);
    }

    /**
     * Rule metadata
     *
     * @return
     */
    public Iterator<YaraMeta> getMetadata() {
        return new GenericIterator<YaraMeta>() {
            private long index = library.ruleMetas(peer);

            @Override
            protected YaraMetaImpl getNext() {
                long last = index;
                index = library.ruleMetaNext(index);

                if (index == 0 || last == 0) {
                    return null;
                }

                return new YaraMetaImpl(library, last);
            }
        };
    }

    /**
     * Rule strings
     *
     * @return
     */
    public Iterator<YaraString> getStrings() {
        return new GenericIterator<YaraString>() {
            private long index = library.ruleStrings(peer);

            @Override
            protected YaraStringImpl getNext() {
                long last = index;
                index = library.ruleStringNext(index);

                if (index == 0 || last == 0) {
                    return null;
                }

                return new YaraStringImpl(library, last);
            }
        };
    }
}
