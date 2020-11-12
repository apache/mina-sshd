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
import java.net.URI;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
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
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.sftp.client.AbstractSftpClientTestSupport;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.client.SftpVersionSelector;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.util.test.CommonTestSupportUtils;

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
        assertEquals("Mismatched read test data", expected, buf);

        if (version >= SftpConstants.SFTP_V4) {
            testAclFileAttributeView(file1);
        }

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
        assertEquals("Mismatched symlink data", expected, new String(Files.readAllBytes(file1), StandardCharsets.UTF_8));

        testFileChannelLock(file1);

        Files.delete(file1);
    }

    protected static Iterable<Path> testRootDirs(FileSystem fs) throws IOException {
        Iterable<Path> rootDirs = fs.getRootDirectories();
        for (Path root : rootDirs) {
            String rootName = root.toString();
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(root)) {
                for (Path child : ds) {
                    String name = child.getFileName().toString();
                    assertNotEquals("Unexpected dot name", ".", name);
                    assertNotEquals("Unexpected dotdot name", "..", name);
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
        assertNotNull("No ACL view for " + file, aclView);

        Map<String, ?> attrs = Files.readAttributes(file, "acl:*", LinkOption.NOFOLLOW_LINKS);
        outputDebugMessage("readAttributes(%s) %s", file, attrs);
        assertEquals("Mismatched owner for " + file, aclView.getOwner(), attrs.get("owner"));

        @SuppressWarnings("unchecked")
        List<AclEntry> acl = (List<AclEntry>) attrs.get("acl");
        outputDebugMessage("acls(%s) %s", file, acl);
        assertListEquals("Mismatched ACLs for " + file, aclView.getAcl(), acl);

        return aclView;
    }

    protected static void testSymbolicLinks(Path link, Path relPath) throws IOException {
        outputDebugMessage("Create symlink %s => %s", link, relPath);
        Files.createSymbolicLink(link, relPath);
        assertTrue("Not a symbolic link: " + link, Files.isSymbolicLink(link));

        Path symLink = Files.readSymbolicLink(link);
        assertEquals("mismatched symbolic link name", relPath.toString(), symLink.toString());

        outputDebugMessage("Delete symlink %s", link);
        Files.delete(link);
    }

    protected static void testFileChannelLock(Path file) throws IOException {
        try (FileChannel channel = FileChannel.open(file)) {
            try (FileLock lock = channel.lock()) {
                outputDebugMessage("Lock %s: %s", file, lock);

                try (FileChannel channel2 = FileChannel.open(file)) {
                    try (FileLock lock2 = channel2.lock()) {
                        fail("Unexpected success in re-locking " + file + ": " + lock2);
                    } catch (OverlappingFileLockException e) {
                        // expected
                    }
                }
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
