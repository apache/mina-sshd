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

package org.apache.sshd.common.util.io;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class DirectoryScannerTest extends JUnitTestSupport {
    public DirectoryScannerTest() {
        super();
    }

    @Test
    public void testDeepScanning() throws IOException {
        Path rootDir = getTempTargetRelativeFile(getClass().getSimpleName(), getCurrentTestName());
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

        DirectoryScanner ds = new DirectoryScanner(rootDir, "**/*");
        List<Path> actual = ds.scan(ArrayList::new);
        Collections.sort(actual);
        assertListEquals(getCurrentTestName(), expected, actual);
    }

    @Test
    public void testFileSuffixMatching() throws IOException {
        Path rootDir = getTempTargetRelativeFile(getClass().getSimpleName(), getCurrentTestName());
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

        DirectoryScanner ds = new DirectoryScanner(rootDir, "*.txt");
        List<Path> actual = ds.scan(ArrayList::new);
        Collections.sort(actual);
        assertListEquals(getCurrentTestName(), expected, actual);
    }
}
