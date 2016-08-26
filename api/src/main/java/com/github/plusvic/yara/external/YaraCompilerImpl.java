package com.github.plusvic.yara.external;

import com.github.plusvic.yara.*;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import static com.github.plusvic.yara.Preconditions.checkArgument;

public class YaraCompilerImpl implements YaraCompiler {
    private static final Logger LOGGER = Logger.getLogger(YaraCompilerImpl.class.getName());

    private YaraCompilationCallback callback;
    private List<Path> packages = new ArrayList<>();
    private YaracExecutable yarac;
    private Path   rules;

    public YaraCompilerImpl() {
        this.rules = null;
        this.yarac = new YaracExecutable();
    }

    @Override
    public void setCallback(YaraCompilationCallback cbk) {
        checkArgument(cbk != null);
        this.callback = cbk;
    }

    @Override
    public void addRulesContent(String content, String namespace) {
        checkArgument(!Utils.isNullOrEmpty(content));

        if (rules != null) {
            // Mimic embedded behavior
            throw new YaraException(ErrorCode.INSUFFICIENT_MEMORY.getValue());
        }

        try {
            String ns = (namespace != null ? namespace : YaracExecutable.GLOBAL_NAMESPACE);
            Path rule = File.createTempFile(UUID.randomUUID().toString(), "yara")
                    .toPath();

            Files.write(rule, content.getBytes(), StandardOpenOption.WRITE);
            yarac.addRule(ns, rule);
        }
        catch (Throwable t) {
            LOGGER.log(Level.WARNING, "Failed to add rule content {0}",
                    t.getMessage());
            throw new RuntimeException(t);
        }
    }

    @Override
    public void addRulesFile(String filePath, String fileName, String namespace) {
        checkArgument(!Utils.isNullOrEmpty(filePath));
        checkArgument(Files.exists(Paths.get(filePath)));

        if (rules != null) {
            // Mimic embedded behavior
            throw new YaraException(ErrorCode.INSUFFICIENT_MEMORY.getValue());
        }

        try {
            String ns = (namespace != null ? namespace : YaracExecutable.GLOBAL_NAMESPACE);
            Path rule = File.createTempFile(UUID.randomUUID().toString(), "yara")
                    .toPath();

            yarac.addRule(ns, Paths.get(filePath));
        }
        catch (Throwable t) {
            LOGGER.log(Level.WARNING, MessageFormat.format("Failed to add rules file {0}: {1}",
                    filePath, t.getMessage()));
            throw new RuntimeException(t);
        }
    }

    @Override
    public void addRulesPackage(String packagePath, String namespace) {
        checkArgument(!Utils.isNullOrEmpty(packagePath));
        checkArgument(Files.exists(Paths.get(packagePath)));

        LOGGER.fine(String.format("Loading package: %s", packagePath));

        try {
            Path unpackedFolder = Files.createTempDirectory(UUID.randomUUID().toString());
            packages.add(unpackedFolder);

            try (ZipInputStream zis = new ZipInputStream(new FileInputStream(packagePath))) {

                for (ZipEntry ze = zis.getNextEntry(); ze != null; ze = zis.getNextEntry()) {
                    // Check yara rule
                    String iname = ze.getName().toLowerCase();
                    if (!(iname.endsWith(".yar") || iname.endsWith(".yara") || iname.endsWith(".yr"))) {
                        continue;
                    }

                    // Read content
                    LOGGER.fine(String.format("Loading package entry: %s", ze.getName()));
                    File ruleFile = new File(unpackedFolder + File.separator + ze.getName());

                    new File(ruleFile.getParent()).mkdirs();

                    byte[] buffer = new byte[1024];

                    try (FileOutputStream fos = new FileOutputStream(ruleFile)) {
                        int len;
                        while ((len = zis.read(buffer)) > 0) {
                            fos.write(buffer, 0, len);
                        }
                    }

                    // Load file
                    addRulesFile(ruleFile.toString(), ze.getName(), namespace);
                }

                zis.closeEntry();
                zis.close();
            }

        }
        catch(IOException ioe){
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public YaraScanner createScanner() {
        try {
            if (rules == null) {
                rules = yarac.compile(callback);
            }
            return new YaraScannerImpl(rules);
        }
        catch (Exception e) {
            throw new YaraException(e.getMessage());
        }
    }

    @Override
    public void close() throws Exception {
        for (Path p : packages) {
            try {
                Files.walkFileTree(p, new SimpleFileVisitor<Path>() {
                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                        Files.delete(file);
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
                        Files.delete(file);
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                        if (exc == null) {
                            Files.delete(dir);
                            return FileVisitResult.CONTINUE;
                        }
                        return FileVisitResult.CONTINUE;
                    }
                });
            }
            catch (IOException ioe) {
                LOGGER.warning(String.format("Failed to delete package %s: %s", p, ioe.getMessage()));
            }
        }
    }
}
