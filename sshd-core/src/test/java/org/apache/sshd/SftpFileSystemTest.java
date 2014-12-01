/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd;

import java.io.File;
import java.net.URI;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Map;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.server.sftp.SftpSubsystem;
import org.apache.sshd.util.BaseTest;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SftpFileSystemTest extends BaseTest {

    private SshServer sshd;
    private int port;

    @Before
    public void setUp() throws Exception {
        sshd = SshServer.setUpDefaultServer();
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystem.Factory()));
        sshd.setCommandFactory(new ScpCommandFactory());
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();
        port = sshd.getPort();
    }

    @After
    public void tearDown() throws Exception {
        sshd.stop(true);
    }

    @Test
    public void testFileSystem() throws Exception {
        Utils.deleteRecursive(new File("target/sftp"));

        FileSystem fs = FileSystems.newFileSystem(URI.create("sftp://x:x@localhost:" + port + "/"), null);
        Path root = fs.getRootDirectories().iterator().next();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(root)) {
            for (Path child : ds) {
                System.out.println(child);
            }
        }
        Path file = fs.getPath("target/sftp/client/test.txt");
        Files.createDirectories(file.getParent());
        Files.write(file, "Hello world\n".getBytes());
        String buf = new String(Files.readAllBytes(file));
        assertEquals("Hello world\n", buf);

        Map<String, Object> attrs = Files.readAttributes(file, "*");
        System.out.println(attrs);

        // TODO: symbolic links only work for absolute files
//        Path link = fs.getPath("target/sftp/client/test2.txt");
//        Files.createSymbolicLink(link, link.relativize(file));
//        assertTrue(Files.isSymbolicLink(link));
//        assertEquals("test.txt", Files.readSymbolicLink(link).toString());

        Path link = fs.getPath("target/sftp/client/test2.txt");
        Files.createSymbolicLink(link, link.getParent().relativize(file));
        assertTrue(Files.isSymbolicLink(link));
        assertEquals("test.txt", Files.readSymbolicLink(link).toString());
        Files.delete(link);

        attrs = Files.readAttributes(file, "*", LinkOption.NOFOLLOW_LINKS);
        System.out.println(attrs);

        buf = new String(Files.readAllBytes(file));
        assertEquals("Hello world\n", buf);

        Files.delete(file);

        fs.close();
    }

    @Test
    public void testRootFileSystem() throws Exception {
        Path rootNative = Paths.get("target/root").toAbsolutePath();
        Utils.deleteRecursive(rootNative.toFile());
        Files.createDirectories(rootNative);

        FileSystem fs = FileSystems.newFileSystem(URI.create("root:" + rootNative.toUri().toString() + "!/"), null);

        Files.createDirectories(fs.getPath("test/foo"));
    }

}
