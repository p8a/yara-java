#ifndef __LIBYARA_H__
#define __LIBYARA_H__

#include "yara.h"
#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif


static jstring
cast_jstring(JNIEnv *env, const char * v) {
    return !v ?NULL :
            (*env)->NewStringUTF(env, v);
}

/*
 * Rule indentifier
 */
static jstring
yara_rule_identifier(JNIEnv *env, void *v) {
    return !v ? NULL :
            cast_jstring(env, ((YR_RULE*)v)->identifier);
}

/*
 *  Tag iteration
 */
static void*
yara_rule_tags(JNIEnv *env, void *v) {
    return !v ? 0 : (void *)((YR_RULE*)v)->tags;
}

static void*
yara_rule_tag_next(JNIEnv *env, void *v) {
    char *n = v;

    if (!n || *n == '\0') {
        return 0;
    }

    for ( ; *n != '\0'; ++n);
    return n + 1;
}

static jstring
yara_tag_string(JNIEnv *env, void *v) {
    return !v ? NULL :
            cast_jstring(env, (char*)v);
}

/*
 *  Metadata iteration
 */
static void*
yara_rule_metas(JNIEnv *env, void *v) {
    return !v ? 0 : ((YR_RULE*)v)->metas;
}

static void*
yara_rule_meta_next(JNIEnv *env, void *v) {
    YR_META *meta = (YR_META *)v;

    if (META_IS_NULL(meta)) {
        return 0;
    }
    return ++meta;
}

static int
yara_meta_type(JNIEnv *env, void* v) {
    return !v ? 0 : ((YR_META*)v)->type;
}

static jstring
yara_meta_identifier(JNIEnv *env, void *v) {
    return !v ? NULL :
            cast_jstring(env, ((YR_META*)v)->identifier);
}

static jstring
yara_meta_string(JNIEnv *env, void *v) {
    return !v ? NULL :
            cast_jstring(env, ((YR_META*)v)->string);
}

static int
yara_meta_integer(JNIEnv *env, void *v) {
    return !v ? 0 : ((YR_META*)v)->integer;
}

/*
 *  Strings iteration
 */
static void*
yara_rule_strings(JNIEnv *env, void *v) {
    return !v ? 0 : ((YR_RULE*)v)->strings;
}

static void*
yara_rule_string_next(JNIEnv *env, void *v) {
    YR_STRING *string = (YR_STRING *)v;

    if (STRING_IS_NULL(string)) {
        return 0;
    }
    return ++string;
}

static jstring
yara_string_identifier(JNIEnv *env, void *v) {
    return !v ? NULL :
            cast_jstring(env, ((YR_STRING*)v)->identifier);
}

static void*
yara_string_matches(JNIEnv *env, void *v) {
    YR_STRING *string = (YR_STRING *)v;
    return (string ? STRING_MATCHES(string).head : NULL);
}

static void*
yara_string_match_next(JNIEnv *env, void *v) {
    return !v ? 0 :
            ((YR_MATCH *)v)->next;
}

static int64_t
yara_match_offset(JNIEnv *env, void *v) {
    return !v ? 0:
            ((YR_MATCH*)v)->offset;
}

static jstring
yara_match_value(JNIEnv *env, void *v) {
    char *buffer = 0;
    YR_MATCH *match = (YR_MATCH *)v;
    jstring value = 0;

    if (!v) {
        return 0;
    }

    if (0 != (buffer = malloc(match->length + 1))) {
        memset(buffer, 0, match->length + 1);
        strncpy(buffer, match->data, match->length);

        value = cast_jstring(env, buffer);

        free(buffer);
    }

    return value;
}

/*
 *  Compilation
 */
static int
yara_compiler_add_file(JNIEnv *env, void *compiler, const char *path, const char *ns, const char *file_name) {
    FILE *fp = fopen(path, "r");
    int ret = 0;

    if (fp) {
        ret = yr_compiler_add_file((YR_COMPILER*)compiler, fp, ns, file_name);
        fclose(fp);
    }
    else {
        ret = 3;
    }

    return ret;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
