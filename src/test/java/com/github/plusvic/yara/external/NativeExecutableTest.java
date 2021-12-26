package com.github.plusvic.yara.external;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * User: pba
 * Date: 6/13/15
 * Time: 8:55 AM
 */
public class NativeExecutableTest {
    @Test
    public void testCreateNoName() {
        assertThrows(IllegalArgumentException.class, () -> new NativeExecutable(""));
    }

    @Test
    public void testCreateNullName() {
        assertThrows(IllegalArgumentException.class,
            () -> new NativeExecutable(null, NativeExecutableTest.class.getClassLoader()));
    }

    @Test
    public void testCreate() {
        new NativeExecutable("yara");
    }

    @Test
    public void testLoadNotFound() {
        NativeExecutable exe = new NativeExecutable(UUID.randomUUID().toString());
        assertFalse(exe.load());
    }

    @Test
    public void testLoadYara() {
        NativeExecutable exe = new NativeExecutable("yara");
        assertTrue(exe.load());
    }

    @Test
    public void testLoadYarac() {
        NativeExecutable exe = new NativeExecutable("yarac");
        assertTrue(exe.load());
    }
}
