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

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class ModifiableFileWatcherTest extends JUnitTestSupport {

    @TempDir
    protected File tmp;

    public ModifiableFileWatcherTest() {
        super();
    }

    // see SSHD-606
    @Test
    void validateStrictConfigFilePermissions() throws IOException {
        Assumptions.assumeTrue(!OsUtils.isWin32(), "Test does not always work on Windows");

        Path file = getTempTargetRelativeFile(getClass().getSimpleName(), getCurrentTestName());
        outputDebugMessage("%s deletion result=%s", file, Files.deleteIfExists(file));
        assertNull(ModifiableFileWatcher.validateStrictConfigFilePermissions(file),
                "Unexpected violation for non-existent file: " + file);

        assertHierarchyTargetFolderExists(file.getParent());
        try (OutputStream output = Files.newOutputStream(file)) {
            output.write((getClass().getName() + "#" + getCurrentTestName() + "@" + new Date(System.currentTimeMillis()))
                    .getBytes(StandardCharsets.UTF_8));
        }

        Collection<PosixFilePermission> perms = IoUtils.getPermissions(file);
        if (GenericUtils.isEmpty(perms)) {
            assertNull(ModifiableFileWatcher.validateStrictConfigFilePermissions(file),
                    "Unexpected violation for no permissions file: " + file);
        } else if (OsUtils.isUNIX()) {
            Map.Entry<String, Object> violation = null;
            for (PosixFilePermission p : ModifiableFileWatcher.STRICTLY_PROHIBITED_FILE_PERMISSION) {
                if (perms.contains(p)) {
                    violation = ModifiableFileWatcher.validateStrictConfigFilePermissions(file);
                    assertNotNull(violation,
                            "Unexpected success for permission=" + p + " of file " + file + " permissions=" + perms);
                    break;
                }
            }

            if (violation == null) { // we do not expected a failure if no permissions have been violated
                assertNull(ModifiableFileWatcher.validateStrictConfigFilePermissions(file),
                        "Unexpected UNIX violation for file " + file + " permissions=" + perms);
            }
        } else {
            assertNull(ModifiableFileWatcher.validateStrictConfigFilePermissions(file),
                    "Unexpected Windows violation for file " + file + " permissions=" + perms);
        }
    }

    @Test
    void symlinkChain() throws Exception {
        Assumptions.assumeFalse(OsUtils.isWin32(), "Symlink test disabled on Windows");
        Path adam = tmp.toPath().resolve("adam");
        Path jeff = adam.getParent().resolve("jeff");
        Path link = adam.getParent().resolve(adam.getFileName() + ".link");
        Path link2 = adam.getParent().resolve("topLink");
        Files.write(adam, "adam".getBytes(StandardCharsets.US_ASCII));
        Files.write(jeff, "jeff".getBytes(StandardCharsets.US_ASCII));
        // Change the last modified time to avoid problems with "racily clean" timestamps
        Files.setLastModifiedTime(adam, FileTime.from(Instant.now().minusSeconds(4)));
        Files.setLastModifiedTime(jeff, Files.getLastModifiedTime(adam));
        Files.createSymbolicLink(link, adam);
        Files.createSymbolicLink(link2, link);
        ModifiableFileWatcher watcher = new ModifiableFileWatcher(link2);
        assertTrue(watcher.checkReloadRequired(), "Should need to reload");
        String data = new String(Files.readAllBytes(link2), StandardCharsets.US_ASCII);
        assertEquals("adam", data);
        watcher.updateReloadAttributes();
        assertFalse(watcher.checkReloadRequired(), "Should not need to reload");
        Files.delete(link);
        Files.createSymbolicLink(link, jeff);
        assertTrue(watcher.checkReloadRequired(), "Should need to reload");
        data = new String(Files.readAllBytes(link2), StandardCharsets.US_ASCII);
        assertEquals("jeff", data);
    }

    @Test
    void fileModified() throws Exception {
        Path adam = tmp.toPath().resolve("adam");
        Files.write(adam, "adam".getBytes(StandardCharsets.US_ASCII));
        Files.setLastModifiedTime(adam, FileTime.from(Instant.now().minusSeconds(6)));
        ModifiableFileWatcher watcher = new ModifiableFileWatcher(adam);
        assertTrue(watcher.checkReloadRequired(), "Should need to reload");
        String data = new String(Files.readAllBytes(adam), StandardCharsets.US_ASCII);
        assertEquals("adam", data);
        assertFalse(watcher.checkReloadRequired(), "Should not need to reload");
        watcher.updateReloadAttributes();
        assertFalse(watcher.checkReloadRequired(), "Should not need to reload");
        Files.write(adam, "adam".getBytes(StandardCharsets.US_ASCII));
        Files.setLastModifiedTime(adam, FileTime.from(Instant.now().minusSeconds(4)));
        assertTrue(watcher.checkReloadRequired(), "Should need to reload");
        watcher.updateReloadAttributes();
        assertFalse(watcher.checkReloadRequired(), "Should not need to reload");
    }

    @Test
    void fileDeleted() throws Exception {
        Path adam = tmp.toPath().resolve("adam");
        Files.write(adam, "adam".getBytes(StandardCharsets.US_ASCII));
        Files.setLastModifiedTime(adam, FileTime.from(Instant.now().minusSeconds(4)));
        ModifiableFileWatcher watcher = new ModifiableFileWatcher(adam);
        assertTrue(watcher.checkReloadRequired(), "Should need to reload");
        String data = new String(Files.readAllBytes(adam), StandardCharsets.US_ASCII);
        assertEquals("adam", data);
        assertFalse(watcher.checkReloadRequired(), "Should not need to reload");
        watcher.updateReloadAttributes();
        assertFalse(watcher.checkReloadRequired(), "Should not need to reload");
        Files.delete(adam);
        assertTrue(watcher.checkReloadRequired(), "Should need to reload");
        watcher.updateReloadAttributes();
        assertFalse(watcher.checkReloadRequired(), "Should not need to reload");
    }

    @Test
    void fileCreated() throws Exception {
        Path adam = tmp.toPath().resolve("adam");
        ModifiableFileWatcher watcher = new ModifiableFileWatcher(adam);
        assertTrue(watcher.checkReloadRequired(), "Should need to reload");
        watcher.updateReloadAttributes();
        Files.write(adam, "adam".getBytes(StandardCharsets.US_ASCII));
        Files.setLastModifiedTime(adam, FileTime.from(Instant.now().minusSeconds(4)));
        assertTrue(watcher.checkReloadRequired(), "Should need to reload");
        String data = new String(Files.readAllBytes(adam), StandardCharsets.US_ASCII);
        assertEquals("adam", data);
        assertFalse(watcher.checkReloadRequired(), "Should not need to reload");
        watcher.updateReloadAttributes();
        assertFalse(watcher.checkReloadRequired(), "Should not need to reload");
    }

    @Test
    void loadDirectly() throws Exception {
        Path adam = tmp.toPath().resolve("adam");
        Files.write(adam, "adam".getBytes(StandardCharsets.US_ASCII));
        Files.setLastModifiedTime(adam, FileTime.from(Instant.now().minusSeconds(6)));
        ModifiableFileWatcher watcher = new ModifiableFileWatcher(adam);
        String data = new String(Files.readAllBytes(adam), StandardCharsets.US_ASCII);
        assertEquals("adam", data);
        // No call to checkReloadRequired() before.
        watcher.updateReloadAttributes();
        assertFalse(watcher.checkReloadRequired(), "Should not need to reload");
        Files.write(adam, "adam".getBytes(StandardCharsets.US_ASCII));
        Files.setLastModifiedTime(adam, FileTime.from(Instant.now().minusSeconds(4)));
        assertTrue(watcher.checkReloadRequired(), "Should need to reload");
    }

    @Test
    void racyFile() throws Exception {
        Path adam = tmp.toPath().resolve("adam");
        Files.write(adam, "adam".getBytes(StandardCharsets.US_ASCII));
        Files.setLastModifiedTime(adam, FileTime.from(Instant.now()));
        FileTime timestamp = Files.getLastModifiedTime(adam);
        ModifiableFileWatcher watcher = new ModifiableFileWatcher(adam);
        assertTrue(watcher.checkReloadRequired(), "Should need to reload");
        String data = new String(Files.readAllBytes(adam), StandardCharsets.US_ASCII);
        assertEquals("adam", data);
        watcher.updateReloadAttributes();
        Instant start = Instant.now();
        Instant stop = null;
        int n = 0;
        while (Duration.between(start, Instant.now()).compareTo(Duration.ofSeconds(10)) <= 0) {
            n++;
            if (watcher.checkReloadRequired()) {
                watcher.updateReloadAttributes();
            } else {
                stop = Instant.now();
                break;
            }
        }
        assertNotNull(stop, "Expected non-racy clean");
        assertTrue(n > 1, "Should have been racy initially");
        assertTrue(Duration.between(timestamp.toInstant(), stop).compareTo(Duration.ofSeconds(2)) >= 0, "Non-racy too early");
    }
}
