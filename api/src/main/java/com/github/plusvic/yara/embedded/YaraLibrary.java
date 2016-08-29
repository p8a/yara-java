package com.github.plusvic.yara.embedded;


import com.github.plusvic.yara.Preconditions;
import org.fusesource.hawtjni.runtime.*;

import java.io.Closeable;
import java.io.IOException;

/**
 * Yara JNI library
 */
@JniClass
public class YaraLibrary implements Closeable {
    private Library library;

    public YaraLibrary() {
        library = new Library("yara-wrapper", YaraLibrary.class);
        library.load();
    }

    /*
        Yara functions
     */
    private final native int yr_initialize();
    public void initialize() {
        Preconditions.checkState(library != null);
        yr_initialize();
    }

    private final native int yr_finalize();

    @Override
    public void close() throws IOException {
        if (library != null) {
            yr_finalize();
            library = null;
        }
    }

    /*
        Compilation
     */
    private final native int yr_compiler_create(@JniArg(cast = "YR_COMPILER **") long[] compilerRef);
    public int compilerCreate(long[] compilerRef) {
        Preconditions.checkState(library != null);
        return yr_compiler_create(compilerRef);
    }

    private final native void yr_compiler_destroy(@JniArg(cast = "YR_COMPILER *") long compiler);
    public void compilerDestroy(long compiler) {
        Preconditions.checkState(library != null);
        yr_compiler_destroy(compiler);
    }

    private final native void yr_compiler_set_callback(
            @JniArg(cast = "YR_COMPILER*") long compiler,
            @JniArg(cast = "void (*)(int, const char*, int, const char*,void*)", flags = ArgFlag.POINTER_ARG) long callback,
            @JniArg(cast = "void *") long data
    );
    public void compilerSetCallback(long compiler, long callback, long data) {
        Preconditions.checkState(library != null);
        yr_compiler_set_callback(compiler, callback, data);
    }

    private final native int yr_compiler_add_string(
            @JniArg(cast = "YR_COMPILER *") long compiler,
            String rules,
            String namespace);
    public int compilerAddString(long compiler, String rules, String namespace) {
        Preconditions.checkState(library != null);
        return yr_compiler_add_string(compiler, rules, namespace);
    }

    private final native int yara_compiler_add_file(
            JNIEnv evn,
            @JniArg(cast = "YR_COMPILER *") long compiler,
            String filePath,
            String namespace,
            String fileName);
    public int compilerAddFile(long compiler, String filePath, String namespace, String fileName) {
        Preconditions.checkState(library != null);
        return yara_compiler_add_file(null, compiler, filePath, namespace, fileName);
    }

    private final native int yr_compiler_get_rules(
            @JniArg(cast = "YR_COMPILER*") long compiler,
            @JniArg(cast = "YR_RULES**") long[] rules);
    public int compilerGetRules(long compiler, long[] rules) {
        Preconditions.checkState(library != null);
        return yr_compiler_get_rules(compiler, rules);
    }

    private final native int yr_rules_destroy(@JniArg(cast = "YR_RULES*") long rules);
    public int rulesDestroy(long rules) {
        Preconditions.checkState(library != null);
        return yr_rules_destroy(rules);
    }


    @JniMethod
    private final native int yr_rules_scan_file(
            @JniArg(cast = "YR_RULES*") long rules,
            String filename,
            int flags,
            @JniArg(cast = "YR_CALLBACK_FUNC") long callback,
            @JniArg(cast = "void*") long user_data,
            int timeout);
    public int rulesScanFile(long rules, String filename, int flags, long callback, long user_data, int timeout) {
        Preconditions.checkState(library != null);
        return yr_rules_scan_file(rules, filename, flags, callback, user_data, timeout);
    }


    /*
        Mapping helpers
     */
    private final native String cast_jstring(JNIEnv env, @JniArg(cast = "const char*") long pv);
    public String toString(long pv) {
        Preconditions.checkState(library != null);
        return cast_jstring(null, pv);
    }

    /*
        Rules
     */
    private final native String yara_rule_identifier(JNIEnv env, @JniArg(cast = "void*") long pv);
    public String ruleIdentifier(long pv) {
        Preconditions.checkState(library != null);
        return yara_rule_identifier(null, pv);
    }

    private final native long yara_rule_tags(JNIEnv env, @JniArg(cast = "void*") long pv);
    public long ruleTags(long pv) {
        Preconditions.checkState(library != null);
        return yara_rule_tags(null, pv);
    }
    private final native long yara_rule_tag_next(JNIEnv env, @JniArg(cast = "void*") long pv);
    public long ruleTagNext(long pv) {
        Preconditions.checkState(library != null);
        return yara_rule_tag_next(null, pv);
    }

    private final native long yara_rule_metas(JNIEnv env, @JniArg(cast = "void*") long pv);
    public long ruleMetas(long pv) {
        Preconditions.checkState(library != null);
        return yara_rule_metas(null, pv);
    }

    private final native long yara_rule_meta_next(JNIEnv env, @JniArg(cast = "void*") long pv);
    public long ruleMetaNext(long pv) {
        Preconditions.checkState(library != null);
        return yara_rule_meta_next(null, pv);
    }

    private final native long yara_rule_strings(JNIEnv env, @JniArg(cast = "void*") long pv);
    public long ruleStrings(long pv) {
        Preconditions.checkState(library != null);
        return yara_rule_strings(null, pv);
    }

    private final native long yara_rule_string_next(JNIEnv env, @JniArg(cast = "void*") long pv);
    public long ruleStringNext(long pv) {
        Preconditions.checkState(library != null);
        return yara_rule_string_next(null, pv);
    }

    /*
        Tags
     */
    private final native String yara_tag_string(JNIEnv env, @JniArg(cast = "void*") long pv);
    public String tagString(long pv) {
        Preconditions.checkState(library != null);
        return yara_tag_string(null, pv);
    }

    /*
        Metas
    */
    private final native int yara_meta_type(JNIEnv env, @JniArg(cast = "void*") long pv);
    public int metaType(long pv) {
        Preconditions.checkState(library != null);
        return yara_meta_type(null, pv);
    }

    private final native String yara_meta_identifier(JNIEnv env, @JniArg(cast = "void*") long pv);
    public String metaIdentifier(long pv) {
        Preconditions.checkState(library != null);
        return yara_meta_identifier(null, pv);
    }

    private final native String yara_meta_string(JNIEnv env, @JniArg(cast = "void*") long pv);
    public String metaString(long pv) {
        Preconditions.checkState(library != null);
        return yara_meta_string(null, pv);
    }

    private final native int yara_meta_integer(JNIEnv env, @JniArg(cast = "void*") long pv);
    public int metaInteger(long pv) {
        Preconditions.checkState(library != null);
        return yara_meta_integer(null, pv);
    }

    /*
        Strings
     */
    private final native String yara_string_identifier(JNIEnv env, @JniArg(cast = "void*") long pv);
    public String stringIdentifier(long pv) {
        Preconditions.checkState(library != null);
        return yara_string_identifier(null, pv);
    }

    private final native long yara_string_matches(JNIEnv env, @JniArg(cast = "void*") long pv);
    public long stringMatches(long pv) {
        Preconditions.checkState(library != null);
        return yara_string_matches(null, pv);
    }

    private final native long yara_string_match_next(JNIEnv env, @JniArg(cast = "void*") long pv);
    public long stringMatchNext(long pv) {
        Preconditions.checkState(library != null);
        return yara_string_match_next(null, pv);
    }

    /*
        Matches
     */
    private final native long yara_match_offset(JNIEnv env, @JniArg(cast = "void*") long pv);
    public long matchOffset(long pv) {
        Preconditions.checkState(library != null);
        return yara_match_offset(null, pv);
    }

    private final native String yara_match_value(JNIEnv env, @JniArg(cast = "void*") long pv);
    public String matchValue(long pv) {
        Preconditions.checkState(library != null);
        return yara_match_value(null, pv);
    }

    /*
        Modules
     */
    private final native String yara_module_name(JNIEnv env, @JniArg(cast = "void*") long pv);
    public String moduleName(long pv) {
        Preconditions.checkState(library != null);
        return yara_module_name(null, pv);
    }

    private final native long yara_module_load_data(JNIEnv env, @JniArg(cast = "void*") long pv, String data);
    public long moduleLoadData(long pv, String data) {
        Preconditions.checkState(library != null);
        return yara_module_load_data(null, pv, data);
    }

    private final native void yara_module_unload_data(JNIEnv env, @JniArg(cast = "void*") long pv);
    public void moduleUnloadData(long pv) {
        Preconditions.checkState(library != null);
        yara_module_unload_data(null, pv);
    }
}
