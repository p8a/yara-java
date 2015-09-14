package com.github.plusvic.yara.embedded;

import com.github.plusvic.yara.*;
import org.fusesource.hawtjni.runtime.Callback;

import static com.github.plusvic.yara.Preconditions.checkArgument;
import static com.github.plusvic.yara.Preconditions.checkState;

/**
 * Yara compiler
 */
public class YaraCompilerImpl implements YaraCompiler {
    /**
     * Native compilation callback wrapper
     */
    private class NativeCompilationCallback {
        private final YaraLibrary library;
        private final YaraCompilationCallback callback;

        public NativeCompilationCallback(YaraLibrary library, YaraCompilationCallback callback) {
            this.library = library;
            this.callback = callback;
        }

        long nativeOnError(long errorLevel, long fileName, long lineNumber, long message, long data) {
            callback.onError(YaraCompilationCallback.ErrorLevel.from((int) errorLevel),
                    library.toString(fileName),
                    lineNumber,
                    library.toString(message));
            return 0;
        }
    }

    private YaraLibrary library;
    private long        peer;
    private Callback    callback;

    YaraCompilerImpl(YaraLibrary library, long compiler) {
        checkArgument(library != null);
        checkArgument(compiler != 0);

        this.library = library;
        this.peer = compiler;
    }

    @Override
    protected void finalize() throws Throwable {
        close();
        super.finalize();
    }

    /**
     * Set compilation callback
     * @param cbk
     */
    public void setCallback(YaraCompilationCallback cbk) {
        checkArgument(cbk != null);
        checkState(callback == null);

        callback = new Callback(new NativeCompilationCallback(library, cbk), "nativeOnError", 5);
        library.compilerSetCallback(peer, callback.getAddress(), 0);
    }

    /**
     * Release compiler instance
     * @throws Exception
     */
    public void close() throws Exception {
        if (callback != null) {
            callback.dispose();
            callback = null;
        }

        if (peer != 0) {
            library.compilerDestroy(peer);
            peer = 0;
        }

        library = null;
    }

    /**
     * Add rules content
     * @param content
     * @param namespace
     * @return
     */
    public boolean addRules(String content, String namespace) {
        return 0 == library.compilerAddString(peer, content, namespace);
    }

    /**
     * Create scanner
     * @return
     */
    public YaraScanner createScanner() {
        int ret = 0;

        long rules[] = new long[1];
        if (0 != (ret = library.compilerGetRules(peer, rules))) {
            throw new YaraException(ret);
        }

        return new YaraScannerImpl(library, rules[0]);
    }
}
