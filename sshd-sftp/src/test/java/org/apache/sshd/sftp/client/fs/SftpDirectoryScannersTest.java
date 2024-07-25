/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.sftp.client.fs;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;

import org.apache.sshd.common.util.io.DirectoryScanner;
import org.apache.sshd.common.util.io.PathUtils;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.Attributes;
import org.apache.sshd.sftp.client.SftpClient.DirEntry;
import org.apache.sshd.sftp.client.fs.SftpClientDirectoryScanner.ScanDirEntry;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
public class SftpDirectoryScannersTest extends AbstractSftpFilesSystemSupport {
    public SftpDirectoryScannersTest() throws IOException {
        super();
    }

    @BeforeEach
    void setUp() throws Exception {
        setupServer();
    }

    @Test
    void sftpPathDirectoryScannerDeepScanning() throws IOException {
        testSftpPathDirectoryScanner(setupDeepScanning(), "**/*");
    }

    @Test
    void sftpPathDirectoryScannerFileSuffixMatching() throws IOException {
        testSftpPathDirectoryScanner(setupFileSuffixMatching(), "*.txt");
    }

    private void testSftpPathDirectoryScanner(SetupDetails setup, String pattern) throws IOException {
        List<Path> expected = setup.getExpected();
        List<Path> actual;
        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), Collections.emptyMap())) {
            String remDirPath = setup.getRemoteFilePath();
            Path basedir = fs.getPath(remDirPath);
            DirectoryScanner ds = new SftpPathDirectoryScanner(basedir, pattern);
            actual = ds.scan(() -> new ArrayList<>(expected.size()));
        }
        Collections.sort(actual);

        assertListEquals(getCurrentTestName(), expected, actual, PathUtils.EQ_CASE_SENSITIVE_FILENAME);
    }

    @Test
    void sftpClientDirectoryScannerDeepScanning() throws IOException {
        testSftpClientDirectoryScanner(setupDeepScanning(), "**/*");
    }

    @Test
    void sftpClientDirectoryScannerFileSuffixMatching() throws IOException {
        testSftpClientDirectoryScanner(setupFileSuffixMatching(), "*.txt");
    }

    // see SSHD-1102
    @Test
    void directoryStreamFilter() throws IOException {
        SetupDetails details = setupFileSuffixMatching();
        List<Path> expected = details.getExpected();
        List<Path> actual = new ArrayList<>();
        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), Collections.emptyMap())) {
            DirectoryStream.Filter<Path> filter = p -> {
                if (Files.isDirectory(p)) {
                    return true;
                }

                if (!Files.isRegularFile(p)) {
                    return false;
                }

                return p.getFileName().toString().endsWith(".txt");
            };
            collectMatchingFiles(fs.getPath(details.getRemoteFilePath()), filter, actual);
        }

        Collections.sort(actual);

        assertListEquals(getCurrentTestName(), expected, actual, PathUtils.EQ_CASE_SENSITIVE_FILENAME);
    }

    private static void collectMatchingFiles(
            Path dir, DirectoryStream.Filter<? super Path> filter, Collection<Path> matches)
            throws IOException {
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, filter)) {
            for (Path p : ds) {
                assertTrue(filter.accept(p), "Unfiltered path: " + p);

                if (Files.isDirectory(p)) {
                    collectMatchingFiles(p, filter, matches);
                } else if (Files.isRegularFile(p)) {
                    matches.add(p);
                }
            }
        }
    }

    @Test
    void closedDirectoryStreamIteration() throws IOException {
        assertThrows(IllegalStateException.class, () -> {
            SetupDetails details = setupDeepScanning();
            try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), Collections.emptyMap())) {
                Path dir = fs.getPath(details.getRemoteFilePath());
                try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
                    ds.close();

                    for (Path p : ds) {
                        fail("Unexpected iterated path: " + p);
                    }
                }
            }
        });
    }

    @Test
    void directoryStreamRepeatedIteration() throws IOException {
        assertThrows(IllegalStateException.class, () -> {
            SetupDetails details = setupDeepScanning();
            try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), Collections.emptyMap())) {
                Path dir = fs.getPath(details.getRemoteFilePath());
                try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
                    for (Path p : ds) {
                        assertNotNull(p);
                    }

                    for (Path p : ds) {
                        fail("Unexpected iterated path: " + p);
                    }
                }
            }
        });
    }

    @Test
    void directoryStreamClosedEarly() throws IOException {
        Path targetPath = detectTargetFolder();
        Path rootDir = CommonTestSupportUtils.resolve(targetPath, TEMP_SUBFOLDER_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(rootDir);
        Files.createDirectories(rootDir);

        for (int i = 1; i <= 2000; i++) {
            Path file = rootDir.resolve("file" + i + ".txt");
            Files.write(file, file.toString().getBytes(StandardCharsets.UTF_8));
        }

        Path parentPath = targetPath.getParent();
        String remFilePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, rootDir);

        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), Collections.emptyMap())) {
            Path dir = fs.getPath(remFilePath);
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
                int n = 0;
                Iterator<Path> entries = ds.iterator();
                while (entries.hasNext()) {
                    assertNotNull(entries.next());
                    if (n == 0) {
                        ds.close();
                    }
                    n++;
                }

                assertTrue(n > 1, "Expected some read-ahead");
                assertTrue(n < 2000, "Expected early stream end");
                assertThrows(NoSuchElementException.class, () -> entries.next());
            }
        }
    }

    private void testSftpClientDirectoryScanner(SetupDetails setup, String pattern) throws IOException {
        List<Path> expected = setup.getExpected();
        String remRoot = setup.getRemoteFilePath();
        List<ScanDirEntry> actual;
        try (SftpClient sftp = createSingleSessionClient()) {
            SftpClientDirectoryScanner ds = new SftpClientDirectoryScanner(remRoot, pattern);
            actual = ds.scan(sftp, () -> new ArrayList<>(expected.size()));
        }

        assertEquals(expected.size(), actual.size(), "Mismatched result size");

        Collections.sort(expected, PathUtils.BY_CASE_INSENSITIVE_FILENAME);
        Collections.sort(actual, DirEntry.BY_CASE_SENSITIVE_FILENAME);

        Path lclRoot = setup.getRootDir();
        for (int index = 0, count = expected.size(); index < count; index++) {
            Path lclPath = expected.get(index);
            ScanDirEntry remEntry = actual.get(index);
            String filename = remEntry.getFilename();
            assertEquals(Objects.toString(lclPath.getFileName()), filename, "Mismatched name");

            Path relPath = lclRoot.relativize(lclPath);
            String lclRelative = Objects.toString(relPath).replace(File.separatorChar, '/');
            assertEquals(lclRelative, remEntry.getRelativePath(), "Mismatched relative path");

            Attributes attrs = remEntry.getAttributes();
            assertEquals("Mismatched directory indicator for " + filename, Files.isDirectory(lclPath), attrs.isDirectory());
            assertEquals("Mismatched regular file indicator for " + filename, Files.isRegularFile(lclPath),
                    attrs.isRegularFile());
        }
    }

    private SetupDetails setupDeepScanning() throws IOException {
        Path targetPath = detectTargetFolder();
        Path rootDir = CommonTestSupportUtils.resolve(targetPath,
                TEMP_SUBFOLDER_NAME, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(rootDir); // start fresh

        List<Path> expected = new ArrayList<>();
        Path curLevel = rootDir;
        for (int level = 1; level <= 3; level++) {
            Path dir = Files.createDirectories(curLevel.resolve(Integer.toString(level)));
            expected.add(dir);
            Path file = dir.resolve(Integer.toString(level) + ".txt");
            Files.write(file, Collections.singletonList(file.toString()), StandardCharsets.UTF_8);

            expected.add(file);
            curLevel = dir;
        }
        Collections.sort(expected);

        Path parentPath = targetPath.getParent();
        String remFilePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, rootDir);
        return new SetupDetails(rootDir, remFilePath, expected);
    }

    private SetupDetails setupFileSuffixMatching() throws IOException {
        Path targetPath = detectTargetFolder();
        Path rootDir = CommonTestSupportUtils.resolve(targetPath,
                TEMP_SUBFOLDER_NAME, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(rootDir); // start fresh
        Files.createDirectories(rootDir);

        List<Path> expected = new ArrayList<>();
        for (int level = 1; level <= 8; level++) {
            Path file = rootDir.resolve(Integer.toString(level) + (((level & 0x03) == 0) ? ".csv" : ".txt"));
            Files.write(file, Collections.singletonList(file.toString()), StandardCharsets.UTF_8);
            String name = Objects.toString(file.getFileName());
            if (name.endsWith(".txt")) {
                expected.add(file);
            }
        }
        Collections.sort(expected);

        Path parentPath = targetPath.getParent();
        String remFilePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, rootDir);
        return new SetupDetails(rootDir, remFilePath, expected);
    }

    private static class SetupDetails {
        private final Path rootDir;
        private final String remFilePath;
        private final List<Path> expected;

        SetupDetails(Path rootDir, String remFilePath, List<Path> expected) {
            this.rootDir = rootDir;
            this.remFilePath = remFilePath;
            this.expected = expected;
        }

        public Path getRootDir() {
            return rootDir;
        }

        public String getRemoteFilePath() {
            return remFilePath;
        }

        public List<Path> getExpected() {
            return expected;
        }
    }
}
