package com.github.plusvic.yara.embedded;

import com.github.plusvic.yara.Yara;
import com.github.plusvic.yara.YaraCompiler;
import com.github.plusvic.yara.YaraException;

import java.io.IOException;

/**
 * Yara component
 *
 * @apiNote There should be only one component instance per process
 */
public class YaraImpl implements Yara {
    private static final String NOT_INITIALISED = "A call to YaraImpl.initialiseApp() must be called from the main thread of the VM.";
    private static Yara mInstance;


    /**
     * must be called from the main application thread.
     * Do remember to finalise finally, once the application is no longer willing to use the library
     * Refer to documentation @ <a href="http://yara.readthedocs.io/">yara</a>
     */
    public static void initialiseApp() {
        mInstance = new YaraImpl();
    }

    /**
     *
     * must be called from the main thread of the VM.
     * Refer to documentation @ <a href="http://yara.readthedocs.io/">yara</a>
     *
     * @throws IOException
     */
    public static void finaliseApp() throws IOException {
        if (mInstance != null) try {
            mInstance.finalise();
        } finally {
            mInstance = null;
        }
    }

    // TODO: implement finalise thread

    public static YaraCompiler newCompiler() {
        if (mInstance == null) {
            throw new RuntimeException(NOT_INITIALISED);
        }
        return mInstance.createCompiler();
    }


    private YaraLibrary libraryInstance;

    private YaraImpl() {
        libraryInstance = new YaraLibrary();
        libraryInstance.initialize();
    }

    public void finalise() throws IOException {
        if (libraryInstance != null) try {
            libraryInstance.close();
        } finally {
            libraryInstance = null;
        }
    }

    /**
     * Create compiler
     *
     * @return
     */
    public YaraCompiler createCompiler() {
        long compiler[] = new long[1];

        int ret = libraryInstance.compilerCreate(compiler);
        if (ret != 0) {
            throw new YaraException(ret);
        }

        return new YaraCompilerImpl(this.libraryInstance, compiler[0]);
    }

    @Override
    public void close() throws Exception {
        //        finalise();
    }

    /**
     * The singleton serves non thread safe static helpers
     * No need to use instance reference, rather collect objects using helpers
     *
     * @return YaraImpl
     */
    @Deprecated
    public static Yara instance() {
        return mInstance;
    }
}
