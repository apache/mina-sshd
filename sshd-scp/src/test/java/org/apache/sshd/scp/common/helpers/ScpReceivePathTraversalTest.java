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
package org.apache.sshd.scp.common.helpers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.scp.common.ScpHelper;
import org.apache.sshd.scp.common.ScpTransferEventListener;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ScpReceivePathTraversalTest {

    @TempDir
    Path tempDir;

    @Test
    void receiveFileNameCannotEscapeRequestedDirectory() throws Exception {
        Path requestedDirectory = Files.createDirectories(tempDir.resolve("requested"));
        Path outsideFile = requestedDirectory.resolve("..").resolve("outside.txt").normalize();
        byte[] payload = "written outside requested directory".getBytes(StandardCharsets.UTF_8);
        ByteArrayInputStream input = new ByteArrayInputStream(scpFileReceiveScript("../outside.txt", payload));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ScpHelper helper = new ScpHelper(Mockito.mock(Session.class), input, StandardCharsets.UTF_8, output,
                StandardCharsets.UTF_8, FileSystems.getDefault(), new NonSyncScpFileOpener(), ScpTransferEventListener.EMPTY);
        assertThrows(IOException.class, () -> helper.receive("scp -t " + requestedDirectory, requestedDirectory, false, false,
                false, ScpHelper.MIN_RECEIVE_BUFFER_SIZE));
        assertFalse(Files.exists(outsideFile), "remote SCP name should not escape the requested directory");
        assertFalse(Files.exists(requestedDirectory.resolve("outside.txt")));
    }

    @Test
    void receiveFileNameCannotOverwriteExistingFileOutsideRequestedDirectory() throws Exception {
        Path requestedDirectory = Files.createDirectories(tempDir.resolve("requested"));
        Path simulatedAutoloadedConfig = requestedDirectory.resolve("..").resolve("simulated-autoloaded-config.txt")
                .normalize();
        byte[] originalData = "original safe config".getBytes(StandardCharsets.UTF_8);
        Files.write(simulatedAutoloadedConfig, originalData);
        byte[] payload = "attacker-controlled benign marker".getBytes(StandardCharsets.UTF_8);
        ByteArrayInputStream input = new ByteArrayInputStream(
                scpFileReceiveScript("../simulated-autoloaded-config.txt", payload));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ScpHelper helper = new ScpHelper(Mockito.mock(Session.class), input, StandardCharsets.UTF_8, output,
                StandardCharsets.UTF_8, FileSystems.getDefault(), new NonSyncScpFileOpener(), ScpTransferEventListener.EMPTY);
        assertThrows(IOException.class, () -> helper.receive("scp -t " + requestedDirectory, requestedDirectory, false, false,
                false, ScpHelper.MIN_RECEIVE_BUFFER_SIZE));
        assertArrayEquals(originalData, Files.readAllBytes(simulatedAutoloadedConfig));
        assertFalse(Files.exists(requestedDirectory.resolve("simulated-autoloaded-config.txt")));
    }

    @Test
    void receiveDirectoryNameCannotEscapeRequestedDirectory() throws Exception {
        Path requestedDirectory = Files.createDirectories(tempDir.resolve("requested"));
        Path outsideDirectory = requestedDirectory.resolve("..").resolve("outside-dir").normalize();
        ByteArrayInputStream input = new ByteArrayInputStream(scpDirectoryReceiveScript("../outside-dir"));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ScpHelper helper = new ScpHelper(Mockito.mock(Session.class), input, StandardCharsets.UTF_8, output,
                StandardCharsets.UTF_8, FileSystems.getDefault(), new NonSyncScpFileOpener(), ScpTransferEventListener.EMPTY);
        assertThrows(IOException.class, () -> helper.receive("scp -rt " + requestedDirectory, requestedDirectory, true, false,
                false, ScpHelper.MIN_RECEIVE_BUFFER_SIZE));
        assertFalse(Files.isDirectory(outsideDirectory), "remote SCP directory name should not escape the requested directory");
        assertFalse(Files.exists(requestedDirectory.resolve("outside-dir")));
    }

    private static byte[] scpFileReceiveScript(String name, byte[] payload) throws IOException {
        ByteArrayOutputStream script = new ByteArrayOutputStream();
        script.write(("C0644 " + payload.length + " " + name + "\n").getBytes(StandardCharsets.UTF_8));
        script.write(payload);
        script.write(ScpAckInfo.OK);
        return script.toByteArray();
    }

    private static byte[] scpDirectoryReceiveScript(String name) throws IOException {
        ByteArrayOutputStream script = new ByteArrayOutputStream();
        script.write(("D0755 0 " + name + "\n").getBytes(StandardCharsets.UTF_8));
        script.write((ScpDirEndCommandDetails.HEADER + "\n").getBytes(StandardCharsets.UTF_8));
        return script.toByteArray();
    }

    private static final class NonSyncScpFileOpener extends DefaultScpFileOpener {
        @Override
        public OutputStream openWrite(
                Session session, Path file, long size, Set<PosixFilePermission> permissions,
                OpenOption... options) throws IOException {
            return Files.newOutputStream(file, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
        }
    }
}
