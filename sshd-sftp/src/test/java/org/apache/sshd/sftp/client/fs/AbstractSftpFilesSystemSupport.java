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
import java.io.OutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.sftp.client.AbstractSftpClientTestSupport;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.client.SftpVersionSelector;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.util.test.CommonTestSupportUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSftpFilesSystemSupport extends AbstractSftpClientTestSupport {
    protected AbstractSftpFilesSystemSupport() throws IOException {
        super();
    }

    protected void testFileSystem(FileSystem fs, int version) throws Exception {
        testRootDirs(fs);

        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath,
                SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        Path current = fs.getPath(".").toRealPath().normalize();
        outputDebugMessage("CWD: %s", current);

        Path parentPath = targetPath.getParent();
        Path clientFolder = lclSftp.resolve("client");
        String remFile1Path = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, clientFolder.resolve("file-1.txt"));
        Path file1 = fs.getPath(remFile1Path);
        assertHierarchyTargetFolderExists(file1.getParent());

        String expected = "Hello world: " + getCurrentTestName();
        outputDebugMessage("Write initial data to %s", file1);
        Files.write(file1, expected.getBytes(StandardCharsets.UTF_8));
        String buf = new String(Files.readAllBytes(file1), StandardCharsets.UTF_8);
        assertEquals(expected, buf, "Mismatched read test data");

        try (OutputStream out = file1.getFileSystem().provider().newOutputStream(file1, StandardOpenOption.APPEND)) {
            out.write("xyz".getBytes(StandardCharsets.US_ASCII));
        }
        expected += "xyz";
        buf = new String(Files.readAllBytes(file1), StandardCharsets.UTF_8);
        assertEquals(expected, buf, "Mismatched read test data");

        // Neither WRITE nor APPEND given: READ is default, and CREATE_NEW or TRUNCATE_EXISTING should be ignored.
        assertEquals(expected,
                readFromChannel(file1, StandardOpenOption.CREATE_NEW, StandardOpenOption.TRUNCATE_EXISTING),
                "Mismatched read test data");

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> readFromChannel(file1, StandardOpenOption.APPEND, StandardOpenOption.TRUNCATE_EXISTING));
        assertTrue(ex.getMessage().contains("APPEND"), "unexpected exception message " + ex.getMessage());
        assertTrue(ex.getMessage().contains("TRUNCATE_EXISTING"), "unexpected exception message " + ex.getMessage());

        ex = assertThrows(IllegalArgumentException.class,
                () -> readFromChannel(file1, StandardOpenOption.APPEND, StandardOpenOption.READ));
        assertTrue(ex.getMessage().contains("APPEND"), "unexpected exception message " + ex.getMessage());
        assertTrue(ex.getMessage().contains("READ"), "unexpected exception message " + ex.getMessage());

        assertEquals(expected,
                readFromChannel(file1, StandardOpenOption.READ, StandardOpenOption.WRITE),
                "Mismatched read test data");

        if (version >= SftpConstants.SFTP_V4) {
            testAclFileAttributeView(file1);
        }

        assertEquals("", readFromChannel(file1, StandardOpenOption.READ, StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING), "Mismatched read test data");

        // Restore file contents, other tests need it.
        Files.write(file1, expected.getBytes(StandardCharsets.UTF_8));

        String remFile2Path = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, clientFolder.resolve("file-2.txt"));
        Path file2 = fs.getPath(remFile2Path);
        String remFile3Path = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, clientFolder.resolve("file-3.txt"));
        Path file3 = fs.getPath(remFile3Path);
        try {
            outputDebugMessage("Move with failure expected %s => %s", file2, file3);
            Files.move(file2, file3, LinkOption.NOFOLLOW_LINKS);
            fail("Unexpected success in moving " + file2 + " => " + file3);
        } catch (NoSuchFileException e) {
            // expected
        }

        Files.write(file2, "h".getBytes(StandardCharsets.UTF_8));
        try {
            outputDebugMessage("Move with failure expected %s => %s", file1, file2);
            Files.move(file1, file2, LinkOption.NOFOLLOW_LINKS);
            fail("Unexpected success in moving " + file1 + " => " + file2);
        } catch (FileAlreadyExistsException e) {
            // expected
        }

        outputDebugMessage("Move with success expected %s => %s", file1, file2);
        Files.move(file1, file2, LinkOption.NOFOLLOW_LINKS, StandardCopyOption.REPLACE_EXISTING);
        outputDebugMessage("Move with success expected %s => %s", file2, file1);
        Files.move(file2, file1, LinkOption.NOFOLLOW_LINKS);

        Map<String, Object> attrs = Files.readAttributes(file1, "*");
        outputDebugMessage("%s attributes: %s", file1, attrs);

        // TODO there are many issues with symbolic links on Windows
        if (OsUtils.isUNIX()) {
            Path link = fs.getPath(remFile2Path);
            Path linkParent = link.getParent();
            Path relPath = linkParent.relativize(file1);

            testSymbolicLinks(link, relPath);
        }

        attrs = Files.readAttributes(file1, "*", LinkOption.NOFOLLOW_LINKS);
        outputDebugMessage("%s no-follow attributes: %s", file1, attrs);
        assertEquals(expected, new String(Files.readAllBytes(file1), StandardCharsets.UTF_8), "Mismatched symlink data");

        if (version == SftpConstants.SFTP_V6) {
            testFileChannelLock(file1);
        } else {
            assertThrows(UnsupportedOperationException.class, () -> testFileChannelLock(file1));
        }

        Files.delete(file1);
    }

    protected static String readFromChannel(Path path, StandardOpenOption... options) throws IOException {
        try (FileChannel ch = path.getFileSystem().provider().newFileChannel(path, EnumSet.copyOf(Arrays.asList(options)))) {
            byte[] data = new byte[500];
            ByteBuffer buffer = ByteBuffer.wrap(data);
            int length = 0;
            for (;;) {
                int n = ch.read(buffer);
                if (n < 0) {
                    break;
                }
                length += n;
            }
            return new String(data, 0, length, StandardCharsets.UTF_8);
        }
    }

    protected static Iterable<Path> testRootDirs(FileSystem fs) throws IOException {
        Iterable<Path> rootDirs = fs.getRootDirectories();
        for (Path root : rootDirs) {
            String rootName = root.toString();
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(root)) {
                for (Path child : ds) {
                    String name = child.getFileName().toString();
                    assertNotEquals(".", name, "Unexpected dot name");
                    assertNotEquals("..", name, "Unexpected dotdot name");
                    outputDebugMessage("[%s] %s", rootName, child);
                }
            } catch (IOException | RuntimeException e) {
                // TODO on Windows one might get share problems for *.sys files
                // e.g. "C:\hiberfil.sys: The process cannot access the file because it is being used by another
                // process"
                // for now, Windows is less of a target so we are lenient with it
                if (OsUtils.isWin32()) {
                    System.err.println(
                            e.getClass().getSimpleName() + " while accessing children of root=" + root + ": " + e.getMessage());
                } else {
                    throw e;
                }
            }
        }

        return rootDirs;
    }

    protected static AclFileAttributeView testAclFileAttributeView(Path file) throws IOException {
        outputDebugMessage("getFileAttributeView(%s)", file);
        AclFileAttributeView aclView
                = Files.getFileAttributeView(file, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        assertNotNull(aclView, "No ACL view for " + file);

        Map<String, ?> attrs = Files.readAttributes(file, "acl:*", LinkOption.NOFOLLOW_LINKS);
        outputDebugMessage("readAttributes(%s) %s", file, attrs);
        assertEquals(aclView.getOwner(), attrs.get(IoUtils.OWNER_VIEW_ATTR), "Mismatched owner for " + file);

        @SuppressWarnings("unchecked")
        List<AclEntry> acl = (List<AclEntry>) attrs.get(IoUtils.ACL_VIEW_ATTR);
        outputDebugMessage("acls(%s) %s", file, acl);
        assertListEquals("Mismatched ACLs for " + file, aclView.getAcl(), acl);

        return aclView;
    }

    protected static void testSymbolicLinks(Path link, Path relPath) throws IOException {
        outputDebugMessage("Create symlink %s => %s", link, relPath);
        Files.createSymbolicLink(link, relPath);
        assertTrue(Files.isSymbolicLink(link), "Not a symbolic link: " + link);

        Path symLink = Files.readSymbolicLink(link);
        assertEquals(relPath.toString(), symLink.toString(), "mismatched symbolic link name");

        outputDebugMessage("Delete symlink %s", link);
        Files.delete(link);
    }

    protected static void testFileChannelLock(Path file) throws IOException {
        testFileChannelLockOverlap(file);
        testFileChannelLockWriteRead(file);
        testFileChannelLockWriteWrite(file);
        testFileChannelLockAppendRead(file);
        testFileChannelLockAppendWrite(file);
        testFileChannelLockReadWrite(file);
        testFileChannelLockReadRead(file);
        testFileChannelLockBoth(file);
    }

    protected static void testFileChannelLockOverlap(Path file) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
            try (FileLock lock = channel.lock()) {
                outputDebugMessage("Lock %s: %s", file, lock);

                try (FileChannel channel2 = FileChannel.open(file, StandardOpenOption.WRITE)) {
                    try (FileLock lock2 = channel2.lock()) {
                        fail("Unexpected success in re-locking " + file + ": " + lock2);
                    } catch (OverlappingFileLockException e) {
                        // expected
                    }
                }
            }
        }
    }

    protected static void testFileChannelLockWriteRead(Path file) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
            assertThrows(NonReadableChannelException.class, () -> channel.lock(0, Long.MAX_VALUE, true));
        }
    }

    protected static void testFileChannelLockWriteWrite(Path file) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
            try (FileLock lock = channel.lock()) {
                outputDebugMessage("Lock %s: %s", file, lock);
            }
        }
    }

    protected static void testFileChannelLockAppendRead(Path file) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.APPEND)) {
            assertThrows(NonReadableChannelException.class, () -> channel.lock(0, Long.MAX_VALUE, true));
        }
    }

    protected static void testFileChannelLockAppendWrite(Path file) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.APPEND)) {
            try (FileLock lock = channel.lock()) {
                outputDebugMessage("Lock %s: %s", file, lock);
            }
        }
    }

    protected static void testFileChannelLockReadWrite(Path file) throws IOException {
        try (FileChannel channel = FileChannel.open(file)) {
            assertThrows(NonWritableChannelException.class, () -> channel.lock(0, Long.MAX_VALUE, false));
        }
    }

    protected static void testFileChannelLockReadRead(Path file) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            try (FileLock lock = channel.lock(0, Long.MAX_VALUE, true)) {
                outputDebugMessage("Lock %s: %s", file, lock);
            }
        }
        try (FileChannel channel = FileChannel.open(file)) { // READ is default
            try (FileLock lock = channel.lock(0, Long.MAX_VALUE, true)) {
                outputDebugMessage("Lock %s: %s", file, lock);
            }
        }
    }

    protected static void testFileChannelLockBoth(Path file) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            try (FileLock lock = channel.lock(0, Long.MAX_VALUE, false)) {
                outputDebugMessage("Lock %s: %s", file, lock);
            }
            try (FileLock lock = channel.lock(0, Long.MAX_VALUE, true)) {
                outputDebugMessage("Lock %s: %s", file, lock);
            }
        }
    }

    protected static FileSystem createSftpFileSystem(ClientSession session, SftpVersionSelector selector) throws IOException {
        return SftpClientFactory.instance().createSftpFileSystem(session, selector);
    }

    protected URI createDefaultFileSystemURI() {
        return createDefaultFileSystemURI(Collections.emptyMap());
    }

    protected URI createDefaultFileSystemURI(Map<String, ?> params) {
        return createFileSystemURI(getCurrentTestName(), params);
    }

    protected static URI createFileSystemURI(String username, Map<String, ?> params) {
        return createFileSystemURI(username, port, params);
    }

    protected static URI createFileSystemURI(String username, int port, Map<String, ?> params) {
        return SftpFileSystemProvider.createFileSystemURI(TEST_LOCALHOST, port, username, username, params);
    }
}
