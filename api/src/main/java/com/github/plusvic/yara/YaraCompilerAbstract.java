package com.github.plusvic.yara;


import java.io.File;

/**
 * Created by styagi on 26/08/16.
 */
public abstract class YaraCompilerAbstract implements YaraCompiler {

    @Override
    public int addRulesDirectory(String dir, String namespace, boolean recursive) {
        File d = new File(dir);
        if (!d.isDirectory()) throw new RuntimeException( d.toString() + " is not a directory!");
        int count = 0;
        for (File f : d.listFiles()) {
            if (f.isFile() && isValidRule(f)) {
                addRulesFile(f.getAbsolutePath(), f.getName(), namespace);
                count++;
            } else if (recursive && f.isDirectory()) {
                count += addRulesDirectory(f.getAbsolutePath(), namespace, recursive);
            }
        }
        return count;
    }

    private boolean isValidRule(File f) {
        return f.getName().matches("^.*\\.(yar[a]{0,1}|yr){1}$");
    }
}
