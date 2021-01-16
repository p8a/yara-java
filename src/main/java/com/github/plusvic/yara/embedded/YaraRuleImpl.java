package com.github.plusvic.yara.embedded;

import com.github.plusvic.yara.*;

import java.util.Iterator;

import static com.github.plusvic.yara.Preconditions.checkArgument;

/**
 * Yara rule
 */
public class YaraRuleImpl implements YaraRule {
    private final YaraLibrary library;
    private final long context;
    private final long peer;

    YaraRuleImpl(YaraLibrary library, long context, long peer) {
        checkArgument(library != null);
        checkArgument(context != 0);
        checkArgument(peer != 0);

        this.library = library;
        this.context = context;
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
     * Rule tags
     *
     * @return
     */
    public Iterator<String> getTags() {
        return new GenericIterator<String>() {
            private long index = library.ruleTags(peer);

            @Override
            protected String getNext() {
                long last = index;
                index = library.ruleTagNext(index);

                if (index == 0 || last == 0) {
                    return null;
                }

                return library.tagString(last);
            }
        };
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
                if (index == 0){
                    return null;
                }

                long last = index;
                index = library.ruleMetaNext(index);

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
                if (index == 0){
                    return null;
                }

                long last = index;
                index = library.ruleStringNext(index);

                return new YaraStringImpl(library, context, last);
            }
        };
    }
}
