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

    private static final long CALLBACK_CONTINUE = 0;
    private static final long CALLBACK_ABORT = 1;


    private static final long CALLBACK_MSG_RULE_MATCHING = 1;
    private static final long CALLBACK_MSG_RULE_NOT_MATCHING = 2;
    private static final long CALLBACK_MSG_SCAN_FINISHED = 3;
    private static final long CALLBACK_MSG_IMPORT_MODULE = 4;

    private class NativeScanCallback {
        private boolean negate = false;
        private int maxRules = 0;
        private int count = 0;
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

        public void setNegate(boolean negate) {
            this.negate = negate;
            return;
        }

        public void setMaxRules(int count) {
            checkArgument(count >= 0);
            this.maxRules = count;
        }

        long nativeOnScan(long type, long message, long data) {
            if (!negate && type == CALLBACK_MSG_RULE_MATCHING) {
                ++count;

                if (scanCallback != null) {
                    YaraRuleImpl rule = new YaraRuleImpl(library, message);
                    scanCallback.onMatch(rule);
                }
            }
            else if(negate && type == CALLBACK_MSG_RULE_NOT_MATCHING) {
                ++count;

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

            if (maxRules > 0 && count >= maxRules) {
                return CALLBACK_ABORT;
            }

            return CALLBACK_CONTINUE;
        }
    }

    private YaraLibrary library;
    private YaraScanCallback scanCallback;
    private long peer;
    private int timeout = 60;
    private int maxRules = 0;
    private boolean notSatisfiedOnly = false;

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
    @Override
    public void finalizeThread() {
         if (library != null) {
            library.finalizeThread();
        }   
    }

    /**
     * Set scan timeout
     */
    public void setTimeout(int timeout) {
        checkArgument(timeout >= 0);
        this.timeout = timeout;
    }

    /**
     * Set maximum rules
     * @param count
     */
    @Override
    public void setMaxRules(int count) {
        checkArgument(count > 0);
        this.maxRules = count;
    }

    @Override
    public void setNotSatisfiedOnly(boolean value) {
        this.notSatisfiedOnly = value;
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
        scan(file, moduleArgs, this.scanCallback);
    }

    /**
     * Scan file
     * <br>Use this method for multithreaded operation. When calling this
     * method it is not necessary to set any parameters on the YaraScanner object
     * @param file
     * @param moduleArgs Module arguments (-x)
     */
    @Override
    public void scan(File file, Map<String, String> moduleArgs, YaraScanCallback yaraScanCallback) {
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

        NativeScanCallback nativeCallback = new NativeScanCallback(library, yaraScanCallback, moduleCallback);
        nativeCallback.setMaxRules(maxRules);
        nativeCallback.setNegate(notSatisfiedOnly);

        Callback callback = new Callback(nativeCallback, "nativeOnScan", 3);

        try {
            final long callBackAddress = callback.getAddress();
            if(callBackAddress == 0) {
              throw new IllegalStateException("Too many concurent callbacks, unable to create.");
            }
            int ret = library.rulesScanFile(peer, file.getAbsolutePath(), 0, callBackAddress, 0, timeout);
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
