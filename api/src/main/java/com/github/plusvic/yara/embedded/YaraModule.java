package com.github.plusvic.yara.embedded;

import static com.github.plusvic.yara.Preconditions.checkArgument;

/**
 * Yara module
 */
public class YaraModule implements  AutoCloseable {
    private final YaraLibrary library;
    private final long peer;
    private long dp;

    YaraModule(YaraLibrary library, long peer) {
        checkArgument(library != null);
        checkArgument(peer != 0);

        this.library = library;
        this.peer = peer;
    }

    public String getName() {
        return library.moduleName(peer);
    }

    public boolean loadData(String data) {
        unloadData();

        dp = library.moduleLoadData(peer, data);
        return dp != 0;
    }

    public void unloadData() {
        if (dp != 0) {
            library.moduleUnloadData(dp);
            dp = 0;
        }
    }

    @Override
    public void close() throws Exception {
        unloadData();
    }
}
