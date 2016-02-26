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
package org.apache.sshd.client.subsystem.sftp;

import java.io.IOException;
import java.net.URI;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.scp.ScpCommandFactory;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystem;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystemFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.Utils;
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
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        fileSystemFactory = new VirtualFileSystemFactory(parentPath);
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystemFactory()));
        sshd.setCommandFactory(new ScpCommandFactory());
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
    public void testFileSystem() throws Exception {
        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(),
                new TreeMap<String, Object>() {
                    private static final long serialVersionUID = 1L;    // we're not serializing it

                    {
                        put(SftpFileSystemProvider.READ_BUFFER_PROP_NAME, Integer.valueOf(IoUtils.DEFAULT_COPY_SIZE));
                        put(SftpFileSystemProvider.WRITE_BUFFER_PROP_NAME, Integer.valueOf(IoUtils.DEFAULT_COPY_SIZE));
                    }
                })) {
            assertTrue("Not an SftpFileSystem", fs instanceof SftpFileSystem);
            testFileSystem(fs, ((SftpFileSystem) fs).getVersion());
        }
    }

    @Test   // see SSHD-578
    public void testFileSystemURIParameters() throws Exception {
        Map<String, Object> params = new TreeMap<String, Object>(String.CASE_INSENSITIVE_ORDER);
        params.put("test-class-name", getClass().getSimpleName());
        params.put("test-pkg-name", getClass().getPackage().getName());
        params.put("test-name", getCurrentTestName());

        int expectedVersion = (SftpSubsystem.LOWER_SFTP_IMPL + SftpSubsystem.HIGHER_SFTP_IMPL) / 2;
        params.put(SftpFileSystemProvider.VERSION_PARAM, Integer.valueOf(expectedVersion));
        try (SftpFileSystem fs = (SftpFileSystem) FileSystems.newFileSystem(createDefaultFileSystemURI(params), Collections.<String, Object>emptyMap())) {
            try (SftpClient sftpClient = fs.getClient()) {
                assertEquals("Mismatched negotiated version", expectedVersion, sftpClient.getVersion());

                Session session = sftpClient.getClientSession();
                for (Map.Entry<String, ?> pe : params.entrySet()) {
                    String key = pe.getKey();
                    Object expected = pe.getValue();
                    if (SftpFileSystemProvider.VERSION_PARAM.equalsIgnoreCase(key)) {
                        continue;
                    }

                    Object actual = PropertyResolverUtils.getObject(session, key);
                    assertEquals("Mismatched value for param '" + key + "'", expected, actual);
                }
            }
        }
    }

    @Test
    public void testAttributes() throws IOException {
        Path targetPath = detectTargetFolder();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Utils.deleteRecursive(lclSftp);

        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(),
                new TreeMap<String, Object>() {
                    private static final long serialVersionUID = 1L;    // we're not serializing it

                    {
                        put(SftpFileSystemProvider.READ_BUFFER_PROP_NAME, Integer.valueOf(SftpClient.MIN_READ_BUFFER_SIZE));
                        put(SftpFileSystemProvider.WRITE_BUFFER_PROP_NAME, Integer.valueOf(SftpClient.MIN_WRITE_BUFFER_SIZE));
                    }
                })) {

            Path parentPath = targetPath.getParent();
            Path clientFolder = lclSftp.resolve("client");
            String remFilePath = Utils.resolveRelativeRemotePath(parentPath, clientFolder.resolve("file.txt"));
            Path file = fs.getPath(remFilePath);
            assertHierarchyTargetFolderExists(file.getParent());
            Files.write(file, (getCurrentTestName() + "\n").getBytes(StandardCharsets.UTF_8));

            Map<String, Object> attrs = Files.readAttributes(file, "posix:*");
            assertNotNull("No attributes read for " + file, attrs);

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
        Path targetPath = detectTargetFolder();
        Path rootNative = targetPath.resolve("root").toAbsolutePath();
        Utils.deleteRecursive(rootNative);
        assertHierarchyTargetFolderExists(rootNative);

        try (FileSystem fs = FileSystems.newFileSystem(URI.create("root:" + rootNative.toUri().toString() + "!/"), null)) {
            Path dir = assertHierarchyTargetFolderExists(fs.getPath("test/foo"));
            outputDebugMessage("Created %s", dir);
        }
    }

    @Test
    public void testFileStore() throws IOException {
        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), Collections.<String, Object>emptyMap())) {
            Iterable<FileStore> iter = fs.getFileStores();
            assertTrue("Not a list", iter instanceof List<?>);

            List<FileStore> list = (List<FileStore>) iter;
            assertEquals("Mismatched stores count", 1, list.size());

            FileStore store = list.get(0);
            assertEquals("Mismatched type", SftpConstants.SFTP_SUBSYSTEM_NAME, store.type());
            assertFalse("Read-only ?", store.isReadOnly());

            for (String name : fs.supportedFileAttributeViews()) {
                assertTrue("Unsupported view name: " + name, store.supportsFileAttributeView(name));
            }

            for (Class<? extends FileAttributeView> type : SftpFileSystemProvider.UNIVERSAL_SUPPORTED_VIEWS) {
                assertTrue("Unsupported view type: " + type.getSimpleName(), store.supportsFileAttributeView(type));
            }
        }
    }

    @Test
    public void testMultipleFileStoresOnSameProvider() throws IOException {
        try (SshClient client = setupTestClient()) {
            client.start();

            SftpFileSystemProvider provider = new SftpFileSystemProvider(client);
            Collection<SftpFileSystem> fsList = new LinkedList<>();
            try {
                Collection<String> idSet = new HashSet<>();
                Map<String, Object> empty = Collections.<String, Object>emptyMap();
                for (int index = 0; index < 4; index++) {
                    String credentials = getCurrentTestName() + "-user-" + index;
                    SftpFileSystem expected = provider.newFileSystem(createFileSystemURI(credentials, empty), empty);
                    fsList.add(expected);

                    String id = expected.getId();
                    assertTrue("Non unique file system id: " + id, idSet.add(id));

                    SftpFileSystem actual = provider.getFileSystem(id);
                    assertSame("Mismatched cached instances for " + id, expected, actual);
                    outputDebugMessage("Created file system id: %s", id);
                }

                for (SftpFileSystem fs : fsList) {
                    String id = fs.getId();
                    fs.close();
                    assertNull("File system not removed from cache: " + id, provider.getFileSystem(id));
                }
            } finally {
                IOException err = null;
                for (FileSystem fs : fsList) {
                    try {
                        fs.close();
                    } catch (IOException e) {
                        err = GenericUtils.accumulateException(err, e);
                    }
                }

                client.stop();

                if (err != null) {
                    throw err;
                }
            }
        }
    }

    @Test
    public void testSftpVersionSelector() throws Exception {
        final AtomicInteger selected = new AtomicInteger(-1);
        SftpVersionSelector selector = new SftpVersionSelector() {
            @Override
            public int selectVersion(int current, List<Integer> available) {
                int numAvailable = GenericUtils.size(available);
                Integer maxValue = null;
                if (numAvailable == 1) {
                    maxValue = available.get(0);
                } else {
                    for (Integer v : available) {
                        if (v.intValue() == current) {
                            continue;
                        }

                        if ((maxValue == null) || (maxValue.intValue() < v.intValue())) {
                            maxValue = v;
                        }
                    }
                }

                selected.set(maxValue.intValue());
                return selected.get();
            }
        };
        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (FileSystem fs = session.createSftpFileSystem(selector)) {
                    assertTrue("Not an SftpFileSystem", fs instanceof SftpFileSystem);
                    Collection<String> views = fs.supportedFileAttributeViews();
                    assertTrue("Universal views (" + SftpFileSystem.UNIVERSAL_SUPPORTED_VIEWS + ") not supported: " + views,
                               views.containsAll(SftpFileSystem.UNIVERSAL_SUPPORTED_VIEWS));
                    int expectedVersion = selected.get();
                    assertEquals("Mismatched negotiated version", expectedVersion, ((SftpFileSystem) fs).getVersion());
                    testFileSystem(fs, expectedVersion);
                }
            } finally {
                client.stop();
            }
        }

    }

    private void testFileSystem(FileSystem fs, int version) throws Exception {
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
                // e.g. "C:\hiberfil.sys: The process cannot access the file because it is being used by another process"
                // for now, Windows is less of a target so we are lenient with it
                if (OsUtils.isWin32()) {
                    System.err.println(e.getClass().getSimpleName() + " while accessing children of root=" + root + ": " + e.getMessage());
                } else {
                    throw e;
                }
            }
        }

        Path targetPath = detectTargetFolder();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Utils.deleteRecursive(lclSftp);

        Path current = fs.getPath(".").toRealPath().normalize();
        outputDebugMessage("CWD: %s", current);

        Path parentPath = targetPath.getParent();
        Path clientFolder = lclSftp.resolve("client");
        String remFile1Path = Utils.resolveRelativeRemotePath(parentPath, clientFolder.resolve("file-1.txt"));
        Path file1 = fs.getPath(remFile1Path);
        assertHierarchyTargetFolderExists(file1.getParent());

        String expected = "Hello world: " + getCurrentTestName();
        outputDebugMessage("Write initial data to %s", file1);
        Files.write(file1, expected.getBytes(StandardCharsets.UTF_8));
        String buf = new String(Files.readAllBytes(file1), StandardCharsets.UTF_8);
        assertEquals("Mismatched read test data", expected, buf);

        if (version >= SftpConstants.SFTP_V4) {
            outputDebugMessage("getFileAttributeView(%s)", file1);
            AclFileAttributeView aclView = Files.getFileAttributeView(file1, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            assertNotNull("No ACL view for " + file1, aclView);

            Map<String, ?> attrs = Files.readAttributes(file1, "acl:*", LinkOption.NOFOLLOW_LINKS);
            outputDebugMessage("readAttributes(%s) %s", file1, attrs);
            assertEquals("Mismatched owner for " + file1, aclView.getOwner(), attrs.get("owner"));

            @SuppressWarnings("unchecked")
            List<AclEntry> acl = (List<AclEntry>) attrs.get("acl");
            outputDebugMessage("acls(%s) %s", file1, acl);
            assertListEquals("Mismatched ACLs for " + file1, aclView.getAcl(), acl);
        }

        String remFile2Path = Utils.resolveRelativeRemotePath(parentPath, clientFolder.resolve("file-2.txt"));
        Path file2 = fs.getPath(remFile2Path);
        String remFile3Path = Utils.resolveRelativeRemotePath(parentPath, clientFolder.resolve("file-3.txt"));
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
            outputDebugMessage("Create symlink %s => %s", link, relPath);
            Files.createSymbolicLink(link, relPath);
            assertTrue("Not a symbolic link: " + link, Files.isSymbolicLink(link));

            Path symLink = Files.readSymbolicLink(link);
            assertEquals("mismatched symbolic link name", relPath.toString(), symLink.toString());

            outputDebugMessage("Delete symlink %s", link);
            Files.delete(link);
        }

        attrs = Files.readAttributes(file1, "*", LinkOption.NOFOLLOW_LINKS);
        outputDebugMessage("%s no-follow attributes: %s", file1, attrs);
        assertEquals("Mismatched symlink data", expected, new String(Files.readAllBytes(file1)));

        try (FileChannel channel = FileChannel.open(file1)) {
            try (FileLock lock = channel.lock()) {
                outputDebugMessage("Lock %s: %s", file1, lock);

                try (FileChannel channel2 = FileChannel.open(file1)) {
                    try (FileLock lock2 = channel2.lock()) {
                        fail("Unexpected success in re-locking " + file1 + ": " + lock2);
                    } catch (OverlappingFileLockException e) {
                        // expected
                    }
                }
            }
        }

        Files.delete(file1);
    }

    private URI createDefaultFileSystemURI() {
        return createDefaultFileSystemURI(Collections.<String, Object>emptyMap());
    }

    private URI createDefaultFileSystemURI(Map<String, ?> params) {
        return createFileSystemURI(getCurrentTestName(), params);
    }

    private URI createFileSystemURI(String username, Map<String, ?> params) {
        return createFileSystemURI(username, port, params);
    }

    private static URI createFileSystemURI(String username, int port, Map<String, ?> params) {
        return SftpFileSystemProvider.createFileSystemURI(TEST_LOCALHOST, port, username, username, params);
    }
}
