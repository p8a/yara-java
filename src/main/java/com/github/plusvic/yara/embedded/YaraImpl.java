package com.github.plusvic.yara.embedded;

import com.github.plusvic.yara.Yara;
import com.github.plusvic.yara.YaraCompiler;
import com.github.plusvic.yara.YaraException;

/**
 * Yara component
 *
 * @apiNote There should be only one component instance per process
 */
public class YaraImpl implements Yara {
    private static final YaraLibrary library;

    static {
        library = new YaraLibrary();
        library.initialize();
    }

    /**
     * Create compiler
     *
     * @return
     */
    public YaraCompiler createCompiler() {
        long compiler[] = new long[1];

        int ret = library.compilerCreate(compiler);
        if (ret != 0) {
            throw new YaraException(ret);
        }

        return new YaraCompilerImpl(this.library, compiler[0]);
    }
  
    @Override
    public void finalizeThread() {
        library.finalizeThread();
    }

    @Override
    public void close() throws Exception {
    }
}
