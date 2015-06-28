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
package org.apache.sshd.client.sftp;

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
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.root.RootedFileSystemProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.sftp.SftpConstants;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.server.sftp.SftpSubsystemFactory;
import org.apache.sshd.util.BaseTestSupport;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SftpFileSystemTest extends BaseTestSupport {

    private SshServer sshd;
    private int port;
    private final FileSystemFactory fileSystemFactory;

    public SftpFileSystemTest() throws IOException {
        Path targetPath = detectTargetFolder().toPath();
        Path parentPath = targetPath.getParent();
        final FileSystem fileSystem = new RootedFileSystemProvider().newFileSystem(parentPath, Collections.<String,Object>emptyMap());
        fileSystemFactory = new FileSystemFactory() {
            @Override
            public FileSystem createFileSystem(Session session) throws IOException {
                return fileSystem;
            }
        };
    }

    @Before
    public void setUp() throws Exception {
        sshd = SshServer.setUpDefaultServer();
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystemFactory()));
        sshd.setCommandFactory(new ScpCommandFactory());
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
        sshd.setFileSystemFactory(fileSystemFactory);
        sshd.start();
        port = sshd.getPort();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
    }

    @Test
    public void testFileSystem() throws IOException {
        Path targetPath = detectTargetFolder().toPath();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Utils.deleteRecursive(lclSftp);

        try(FileSystem fs = FileSystems.newFileSystem(
                URI.create("sftp://" + getCurrentTestName() + ":" + getCurrentTestName() + "@localhost:" + port + "/"),
                new TreeMap<String,Object>() {
                    private static final long serialVersionUID = 1L;    // we're not serializing it
                
                    {
                        put(SftpFileSystemProvider.READ_BUFFER_PROP_NAME, Integer.valueOf(IoUtils.DEFAULT_COPY_SIZE));
                        put(SftpFileSystemProvider.WRITE_BUFFER_PROP_NAME, Integer.valueOf(IoUtils.DEFAULT_COPY_SIZE));
                    }
            })) {

            Iterable<Path> rootDirs = fs.getRootDirectories();
            for (Path root : rootDirs) {
                String  rootName = root.toString();
                try (DirectoryStream<Path> ds = Files.newDirectoryStream(root)) {
                    for (Path child : ds) {
                        System.out.append('\t').append('[').append(rootName).append("] ").println(child);
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

            Path current = fs.getPath(".").toRealPath().normalize();
            System.out.append("CWD: ").println(current);

            Path parentPath = targetPath.getParent();
            Path clientFolder = lclSftp.resolve("client");
            String remFile1Path = Utils.resolveRelativeRemotePath(parentPath, clientFolder.resolve(getCurrentTestName() + "-1.txt"));
            Path file1 = fs.getPath(remFile1Path);
            Files.createDirectories(file1.getParent());

            String  expected="Hello world: " + getCurrentTestName();
            {
                Files.write(file1, expected.getBytes());
                String buf = new String(Files.readAllBytes(file1));
                assertEquals("Mismatched read test data", expected, buf);
            }
    
            String remFile2Path = Utils.resolveRelativeRemotePath(parentPath, clientFolder.resolve(getCurrentTestName() + "-2.txt"));
            Path file2 = fs.getPath(remFile2Path);
            String remFile3Path = Utils.resolveRelativeRemotePath(parentPath, clientFolder.resolve(getCurrentTestName() + "-3.txt"));
            Path file3 = fs.getPath(remFile3Path);
            try {
                Files.move(file2, file3);
                fail("Unexpected success in moving " + file2 + " => " + file3);
            } catch (NoSuchFileException e) {
                // expected
            }

            Files.write(file2, "h".getBytes());
            try {
                Files.move(file1, file2);
                fail("Unexpected success in moving " + file1 + " => " + file2);
            } catch (FileAlreadyExistsException e) {
                // expected
            }
            Files.move(file1, file2, StandardCopyOption.REPLACE_EXISTING);
            Files.move(file2, file1);
    
            Map<String, Object> attrs = Files.readAttributes(file1, "*");
            System.out.append(file1.toString()).append(" attributes: ").println(attrs);
    
            // TODO: symbolic links only work for absolute files
    //        Path link = fs.getPath("target/sftp/client/test2.txt");
    //        Files.createSymbolicLink(link, link.relativize(file));
    //        assertTrue(Files.isSymbolicLink(link));
    //        assertEquals("test.txt", Files.readSymbolicLink(link).toString());
    
            // TODO there are many issues with Windows and symbolic links - for now they are of a lesser interest
            if (OsUtils.isUNIX()) {
                Path link = fs.getPath(remFile2Path);
                Path linkParent = link.getParent();
                Path relPath = linkParent.relativize(file1);
                Files.createSymbolicLink(link, relPath);
                assertTrue("Not a symbolic link: " + link, Files.isSymbolicLink(link));

                Path symLink = Files.readSymbolicLink(link);
                assertEquals("mismatched symbolic link name", relPath.toString(), symLink.toString());
                Files.delete(link);
            }
    
            attrs = Files.readAttributes(file1, "*", LinkOption.NOFOLLOW_LINKS);
            System.out.append(file1.toString()).append(" no-follow attributes: ").println(attrs);
    
            assertEquals("Mismatched symlink data", expected, new String(Files.readAllBytes(file1)));
    
            try (FileChannel channel = FileChannel.open(file1)) {
                try (FileLock lock = channel.lock()) {
                    System.out.println("Locked " + lock.toString());
    
                    try (FileChannel channel2 = FileChannel.open(file1)) {
                        try (FileLock lock2 = channel2.lock()) {
                            System.out.println("Locked " + lock2.toString());
                            fail("Unexpected success in re-locking " + file1);
                        } catch (OverlappingFileLockException e) {
                            // expected
                        }
                    }
                }
            }
    
            Files.delete(file1);
        }
    }

    @Test
    public void testAttributes() throws IOException {
        Path targetPath = detectTargetFolder().toPath();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Utils.deleteRecursive(lclSftp);

        try(FileSystem fs = FileSystems.newFileSystem(
                URI.create("sftp://" + getCurrentTestName() + ":" + getCurrentTestName() + "@localhost:" + port + "/"),
                new TreeMap<String,Object>() {
                    private static final long serialVersionUID = 1L;    // we're not serializing it
                
                    {
                        put(SftpFileSystemProvider.READ_BUFFER_PROP_NAME, Integer.valueOf(SftpClient.MIN_READ_BUFFER_SIZE));
                        put(SftpFileSystemProvider.WRITE_BUFFER_PROP_NAME, Integer.valueOf(SftpClient.MIN_WRITE_BUFFER_SIZE));
                    }
            })) {

            Path parentPath = targetPath.getParent();
            Path clientFolder = lclSftp.resolve("client");
            String remFilePath = Utils.resolveRelativeRemotePath(parentPath, clientFolder.resolve(getCurrentTestName() + ".txt"));
            Path file = fs.getPath(remFilePath);
            Files.createDirectories(file.getParent());
            Files.write(file, (getCurrentTestName() + "\n").getBytes());
    
            Map<String, Object> attrs = Files.readAttributes(file, "posix:*");
            assertNotNull("NO attributes read for " + file, attrs);
    
            Files.setAttribute(file, "basic:size", Long.valueOf(2L));
            Files.setAttribute(file, "posix:permissions", PosixFilePermissions.fromString("rwxr-----"));
            Files.setAttribute(file, "basic:lastModifiedTime", FileTime.fromMillis(100000L));

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
    public void testRootFileSystem() throws IOException {
        Path targetPath = detectTargetFolder().toPath();
        Path rootNative = targetPath.resolve("root").toAbsolutePath();
        Utils.deleteRecursive(rootNative);
        Files.createDirectories(rootNative);

        try(FileSystem fs = FileSystems.newFileSystem(URI.create("root:" + rootNative.toUri().toString() + "!/"), null)) {
            Path dir = Files.createDirectories(fs.getPath("test/foo"));
            System.out.println("Created " + dir);
        }
    }
}
