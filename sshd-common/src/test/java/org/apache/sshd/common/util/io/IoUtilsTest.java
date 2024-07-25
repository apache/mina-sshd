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
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class IoUtilsTest extends JUnitTestSupport {
    public IoUtilsTest() {
        super();
    }

    @Test
    void followLinks() {
        assertTrue(IoUtils.followLinks((LinkOption[]) null), "Null ?");
        assertTrue(IoUtils.followLinks(IoUtils.EMPTY_LINK_OPTIONS), "Empty ?");
        assertFalse(IoUtils.followLinks(IoUtils.getLinkOptions(false)), "No-follow ?");
    }

    @Test
    void getEOLBytes() {
        byte[] expected = IoUtils.getEOLBytes();
        assertTrue(NumberUtils.length(expected) > 0, "Empty bytes");

        for (int index = 1; index < Byte.SIZE; index++) {
            byte[] actual = IoUtils.getEOLBytes();
            assertNotSame(expected, actual, "Same bytes received at iteration " + index);
            assertArrayEquals(expected, actual, "Mismatched bytes at iteration " + index);
        }
    }

    /**
     * Tests to make sure check exists does not follow symlinks.
     *
     * @throws IOException on failure
     */
    @Test
    void checkExists() throws IOException {
        Assumptions.assumeFalse(OsUtils.isWin32(), "Not relevant for Windows");
        testCheckExists(Paths.get("target/IoUtilsTest").toAbsolutePath());
    }

    public void testCheckExists(Path baseDir) throws IOException {
        CommonTestSupportUtils.deleteRecursive(baseDir, LinkOption.NOFOLLOW_LINKS);

        Path folder = baseDir.resolve("folder1/folder2/");
        Files.createDirectories(folder);

        Path target = baseDir.resolve("folder1/target");
        Files.createDirectories(target);

        Path dirInTarget = baseDir.resolve("folder1/target/dirintarget");
        Files.createDirectories(dirInTarget);

        Files.createDirectories(target);
        Path link = baseDir.resolve("folder1/folder2/link");
        Files.createSymbolicLink(link, target);

        Path link2 = baseDir.resolve("link");
        Files.createSymbolicLink(link2, target);

        Path targetWithLink = baseDir.resolve("folder1/folder2/link/dirintarget");

        assertTrue(IoUtils.checkFileExists(targetWithLink), "symlink follow should work");
        assertTrue(IoUtils.checkFileExistsAnySymlinks(targetWithLink, false), "symlink follow should work");

        assertFalse(IoUtils.checkFileExistsAnySymlinks(link, true), "Link at end shouldn't be followed");
        assertFalse(IoUtils.checkFileExistsAnySymlinks(targetWithLink, true),
                "Nofollow shouldn't follow directory");
        assertFalse(IoUtils.checkFileExistsAnySymlinks(link2, true),
                "Link at beginning shouldn't be followed");
        assertTrue(IoUtils.checkFileExistsAnySymlinks(baseDir, true),
                "Root directory must exist");
    }
}
