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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.util.Arrays;
import java.util.Map;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.server.sftp.SftpSubsystemFactory;
import org.apache.sshd.util.BaseTest;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class SftpFileSystemTest extends BaseTest {

    private SshServer sshd;
    private int port;

    @Before
    public void setUp() throws Exception {
        sshd = SshServer.setUpDefaultServer();
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystemFactory()));
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

        String uri = "sftp://x:x@localhost:" + port + "/";

        FileSystem fs = FileSystems.newFileSystem(URI.create(uri), null);
        Iterable<Path> rootDirs = fs.getRootDirectories();
        for (Path root : rootDirs) {
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(root)) {
                for (Path child : ds) {
                    System.out.println(child);
                }
            } catch(IOException | RuntimeException e) {
                // TODO on Windows one might get share problems for *.sys files
                // e.g. "C:\hiberfil.sys: The process cannot access the file because it is being used by another process"
                // for now, Windows is less of a target so we are lenient with it
                if (OsUtils.isWin32()) {
                    System.err.println(e.getClass().getSimpleName() + " while accessing children of root=" + root + ": " + e.getMessage());
                } else {
                    throw e;
                }
            }
        }

        Path current = fs.getPath(".").toRealPath();
        Path file = fs.getPath("target/sftp/client/test.txt");
        Files.createDirectories(file.getParent());
        Files.write(file, "Hello world\n".getBytes());
        String buf = new String(Files.readAllBytes(file));
        assertEquals("Hello world\n", buf);

        Path file2 = fs.getPath("target/sftp/client/test2.txt");
        Path file3 = fs.getPath("target/sftp/client/test3.txt");
        try {
            Files.move(file2, file3);
            fail("Expected an IOException");
        } catch (NoSuchFileException e) {
            // expected
        }
        Files.write(file2, "h".getBytes());
        try {
            Files.move(file, file2);
            fail("Expected an IOException");
        } catch (FileAlreadyExistsException e) {
            // expected
        }
        Files.move(file, file2, StandardCopyOption.REPLACE_EXISTING);
        Files.move(file2, file);

        Map<String, Object> attrs = Files.readAttributes(file, "*");
        System.out.println(attrs);

        // TODO: symbolic links only work for absolute files
//        Path link = fs.getPath("target/sftp/client/test2.txt");
//        Files.createSymbolicLink(link, link.relativize(file));
//        assertTrue(Files.isSymbolicLink(link));
//        assertEquals("test.txt", Files.readSymbolicLink(link).toString());

        // TODO there are many issues with Windows and symbolic links - for now they are of a lesser interest
        if (OsUtils.isUNIX()) {
            Path link = fs.getPath("target/sftp/client/test2.txt");
            Files.createSymbolicLink(link, link.getParent().relativize(file));
            assertTrue("Not a symbolic link: " + link, Files.isSymbolicLink(link));
            assertEquals("test.txt", Files.readSymbolicLink(link).toString());
            Files.delete(link);
        }

        attrs = Files.readAttributes(file, "*", LinkOption.NOFOLLOW_LINKS);
        System.out.println(attrs);

        buf = new String(Files.readAllBytes(file));
        assertEquals("Hello world\n", buf);

        try (FileChannel channel = FileChannel.open(file)) {
            try (FileLock lock = channel.lock()) {
                System.out.println("Locked " + lock.toString());

                try (FileChannel channel2 = FileChannel.open(file)) {
                    try (FileLock lock2 = channel2.lock()) {
                        System.out.println("Locked " + lock2.toString());
                        fail("Expected an exception");
                    } catch (OverlappingFileLockException e) {
                        // expected
                    }
                }

            }
        }

        Files.delete(file);

        fs.close();
    }

    @Test
    public void testAttributes() throws Exception {
        Utils.deleteRecursive(new File("target/sftp"));

        try (FileSystem fs = FileSystems.newFileSystem(URI.create("sftp://x:x@localhost:" + port + "/"), null)) {
            Path file = fs.getPath("target/sftp/client/test.txt");
            Files.createDirectories(file.getParent());
            Files.write(file, "Hello world\n".getBytes());
    
            Map<String, Object> attrs = Files.readAttributes(file, "posix:*");
            Assert.assertNotNull("NO attributes read for " + file, attrs);
    
            Files.setAttribute(file, "basic:size", Long.valueOf(2l));
            Files.setAttribute(file, "posix:permissions", PosixFilePermissions.fromString("rwxr-----"));
            Files.setAttribute(file, "basic:lastModifiedTime", FileTime.fromMillis(100000l));

            FileSystem fileSystem = file.getFileSystem();
            try {
                UserPrincipalLookupService userLookupService = fileSystem.getUserPrincipalLookupService();
                GroupPrincipal group = userLookupService.lookupPrincipalByGroupName("everyone");
                Files.setAttribute(file, "posix:group", group);
            } catch (UserPrincipalNotFoundException e) {
                // Also, according to the Javadoc:
                //      "Where an implementation does not support any notion of
                //       group then this method always throws UserPrincipalNotFoundException."
                // Therefore we are lenient with this exception for Windows
                if (OsUtils.isWin32()) {
                    System.err.println(e.getClass().getSimpleName() + ": " + e.getMessage());
                } else {
                    throw e;
                }
            }
        }
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
