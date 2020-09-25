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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiPredicate;

import org.apache.sshd.common.util.io.DirectoryScanner;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SftpDirectoryScannersTest extends AbstractSftpFilesSystemSupport {
    private static final BiPredicate<Path, Path> BY_FILE_NAME = (p1, p2) -> {
        String n1 = Objects.toString(p1.getFileName());
        String n2 = Objects.toString(p2.getFileName());
        return Objects.equals(n1, n2);
    };

    public SftpDirectoryScannersTest() throws IOException {
        super();
    }

    @Before
    public void setUp() throws Exception {
        setupServer();
    }

    @Test
    public void testSftpPathDirectoryScannerDeepScanning() throws IOException {
        testSftpPathDirectoryScanner(setupDeepScanning(), "**/*");
    }

    @Test
    public void testSftpDirectoryScannerFileSuffixMatching() throws IOException {
        testSftpPathDirectoryScanner(setupFileSuffixMatching(), "*.txt");
    }

    private void testSftpPathDirectoryScanner(
            Map.Entry<String, List<Path>> setup, String pattern)
            throws IOException {
        List<Path> expected = setup.getValue();
        List<Path> actual;
        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), Collections.emptyMap())) {
            String remDirPath = setup.getKey();
            Path basedir = fs.getPath(remDirPath);
            DirectoryScanner ds = new SftpPathDirectoryScanner(basedir, pattern);
            actual = ds.scan(() -> new ArrayList<>(expected.size()));
        }
        Collections.sort(actual);

        assertListEquals(getCurrentTestName(), expected, actual, BY_FILE_NAME);
    }

    private Map.Entry<String, List<Path>> setupDeepScanning() throws IOException {
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

        return new SimpleImmutableEntry<>(remFilePath, expected);
    }

    private Map.Entry<String, List<Path>> setupFileSuffixMatching() throws IOException {
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

        return new SimpleImmutableEntry<>(remFilePath, expected);
    }
}
