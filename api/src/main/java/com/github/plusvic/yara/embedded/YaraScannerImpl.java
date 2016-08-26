package com.github.plusvic.yara.embedded;

import com.github.plusvic.yara.*;
import org.fusesource.hawtjni.runtime.Callback;

import java.io.File;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.github.plusvic.yara.Preconditions.checkArgument;

/**
 * User: pba
 * Date: 6/7/15
 * Time: 10:06 AM
 */
public class YaraScannerImpl implements YaraScanner {
    private static final Logger LOGGER = Logger.getLogger(YaraScannerImpl.class.getName());

    private static final long CALLBACK_MSG_RULE_MATCHING = 1;
    private static final long CALLBACK_MSG_RULE_NOT_MATCHING = 2;
    private static final long CALLBACK_MSG_SCAN_FINISHED = 3;
    private static final long CALLBACK_MSG_IMPORT_MODULE = 4;

    private class NativeScanCallback {
        private final YaraLibrary library;
        private final YaraScanCallback scanCallback;
        private final YaraModuleCallback moduleCallback;

        public NativeScanCallback(YaraLibrary library, YaraScanCallback callback) {
            this(library, callback, null);
        }

        public NativeScanCallback(YaraLibrary library, YaraScanCallback scanCallback, YaraModuleCallback moduleCallback) {
            this.library = library;
            this.scanCallback = scanCallback;
            this.moduleCallback = moduleCallback;
        }

        long nativeOnScan(long type, long message, long data) {
            if (type == CALLBACK_MSG_RULE_MATCHING) {
                if (scanCallback != null) {
                    YaraRuleImpl rule = new YaraRuleImpl(library, message);
                    scanCallback.onMatch(rule);
                }
            }
            else if (type == CALLBACK_MSG_IMPORT_MODULE) {
                if (moduleCallback != null) {
                    YaraModule module = new YaraModule(library, message);
                    moduleCallback.onImport(module);
                }
            }

            return 0;
        }
    }

    private YaraLibrary library;
    private YaraScanCallback scanCallback;
    private long peer;
    private int timeout = 60;

    YaraScannerImpl(YaraLibrary library, long rules) {
        checkArgument(library != null);
        checkArgument(rules != 0);

        this.library = library;
        this.peer = rules;
    }

    @Override
    protected void finalize() throws Throwable {
        close();
        super.finalize();
    }

    @Override
    public void close() throws IOException {
        if (peer != 0) {
            library.rulesDestroy(peer);
            peer = 0;
        }
        library = null;
    }

    /**
     * Set scan timeout
     */
    public void setTimeout(int timeout) {
        checkArgument(timeout >= 0);
        this.timeout = timeout;
    }

    /**
     * Set scan callback
     *
     * @param cbk
     */
    public void setCallback(YaraScanCallback cbk) {
        checkArgument(cbk != null);
        this.scanCallback = cbk;
    }

    /**
     * Scan file
     *
     * @param file
     */
    public void scan(File file) {
        scan(file, null);
    }

    /**
     * Scan file
     * @param file
     * @param moduleArgs Module arguments (-x)
     */
    @Override
    public void scan(File file, Map<String, String> moduleArgs) {
        Set<YaraModule> loadedModules = new HashSet<>();

        YaraModuleCallback moduleCallback = null;

        if (moduleArgs != null) {
            moduleCallback = module -> {
                String name = module.getName();

                if (moduleArgs.containsKey(name)) {
                    if (module.loadData(moduleArgs.get(name))) {
                        LOGGER.log(Level.FINE, MessageFormat.format("Loaded module {0} data from {1}",
                                name, moduleArgs.get(name)));

                        loadedModules.add(module);
                    }
                    else {
                        LOGGER.log(Level.WARNING, MessageFormat.format("Failed to load module {0} data from {1}",
                                name, moduleArgs.get(name)));
                    }
                }
            };
        }

        Callback callback = new Callback(new NativeScanCallback(library, scanCallback, moduleCallback),
                "nativeOnScan", 3);

        try {
            int ret = library.rulesScanFile(peer, file.getAbsolutePath(), 0, callback.getAddress(), 0, timeout);
            if (!ErrorCode.isSuccess(ret)) {
                throw new YaraException(ret);
            }
        }
        finally {
            callback.dispose();
            loadedModules.forEach( module -> module.unloadData());
        }
    }
}
