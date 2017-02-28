package com.github.plusvic.yara.external;

import com.github.plusvic.yara.ErrorCode;
import com.github.plusvic.yara.YaraException;
import com.github.plusvic.yara.YaraScanCallback;
import com.github.plusvic.yara.YaraScanner;

import java.io.File;
import java.nio.file.Path;
import java.util.Map;

import static com.github.plusvic.yara.Preconditions.checkArgument;


public class YaraScannerImpl implements YaraScanner {
    private YaraExecutable yara;
    private YaraScanCallback callback;

    public YaraScannerImpl(Path rules) {
        checkArgument(rules != null);
        this.yara = new YaraExecutable();
        this.yara.addRule(rules);
    }

    @Override
    public void setTimeout(int timeout) {
        this.yara.setTimeout(timeout);
    }

    @Override
    public void setMaxRules(int count) {
        yara.setMaxRules(count);
    }

    @Override
    public void setNotSatisfiedOnly(boolean value) {
        yara.setNegate(value);
    }

    @Override
    public void setCallback(YaraScanCallback cbk) {
        checkArgument(cbk != null);
        this.callback = cbk;
    }

    @Override
    public void scan(File file) {
        scan(file, null);
    }

    @Override
    public void scan(File file, Map<String, String> moduleArgs) {
        scan(file, moduleArgs, this.callback);
    }
    @Override
    public void scan(File file, Map<String, String> moduleArgs, YaraScanCallback yaraScanCallback) {
        checkArgument(file != null);

        if (!file.exists()) {
            throw new YaraException(ErrorCode.COULD_NOT_OPEN_FILE.getValue());
        }

        try {
            yara.match(file.toPath(), moduleArgs, yaraScanCallback);
        } catch (Exception e) {
            throw new YaraException(e.getMessage());
        }

    }

    @Override
    public void close() throws Exception {
    }
    @Override
    public void finalizeThread() {
    }
}
