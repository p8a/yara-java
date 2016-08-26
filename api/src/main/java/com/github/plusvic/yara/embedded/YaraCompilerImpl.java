package com.github.plusvic.yara.embedded;

import com.github.plusvic.yara.*;
import org.fusesource.hawtjni.runtime.Callback;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Enumeration;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static com.github.plusvic.yara.Preconditions.checkArgument;
import static com.github.plusvic.yara.Preconditions.checkState;

/**
 * Yara compiler
 */
public class YaraCompilerImpl implements YaraCompiler {
    private static final Logger LOGGER = Logger.getLogger(YaraCompilerImpl.class.getName());

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
    public void addRulesContent(String content, String namespace) {
        int ret  = library.compilerAddString(peer, content, namespace);
        if (ret != ErrorCode.SUCCESS.getValue()) {
            throw new YaraException(ret);
        }
    }

    /** Add rules file
     * @param filePath
     * @param fileName
     * @param namespace
     */
    public void addRulesFile(String filePath, String fileName, String namespace) {
        int ret  = library.compilerAddFile(peer, filePath, namespace, fileName);
        if (ret != ErrorCode.SUCCESS.getValue()) {
            throw new YaraException(ret);
        }
    }

    /**
     * Add rules from package
     * @param packagePath
     * @param namespace
     */
    @Override
    public void addRulesPackage(String packagePath, String namespace) {
        checkArgument(!Utils.isNullOrEmpty(packagePath));
        checkArgument(Files.exists(Paths.get(packagePath)));

        LOGGER.fine(String.format("Loading package: %s", packagePath));

        try (ZipFile zf = new ZipFile(packagePath)) {

            for (Enumeration e = zf.entries(); e.hasMoreElements();) {
                ZipEntry entry = (ZipEntry) e.nextElement();

                // Check yara rule
                String iname = entry.getName().toLowerCase();
                if (!(iname.endsWith(".yar") || iname.endsWith(".yara") || iname.endsWith(".yr"))) {
                    continue;
                }

                // Read content
                LOGGER.fine(String.format("Loading package entry: %s", entry.getName()));
                StringBuilder content = new StringBuilder();

                try (BufferedReader bsr = new BufferedReader(new InputStreamReader(zf.getInputStream(entry)))) {
                    String line;

                    while (null != (line = bsr.readLine())) {
                        content.append(line).append("\n");
                    }
                }

                // Add content
                addRulesContent(content.toString(), namespace);
            }
        }
        catch (IOException ioe) {
            throw new RuntimeException("Failed to load rule package", ioe);
        }
        catch(YaraException yex) {
            throw yex;
        }
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
