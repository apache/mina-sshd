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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.CopyOption;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.Vector;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.subsystem.sftp.SftpClient.CloseableHandle;
import org.apache.sshd.client.subsystem.sftp.SftpClient.OpenMode;
import org.apache.sshd.client.subsystem.sftp.extensions.BuiltinSftpClientExtensions;
import org.apache.sshd.client.subsystem.sftp.extensions.SftpClientExtension;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.channel.WindowClosedException;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.subsystem.sftp.SftpException;
import org.apache.sshd.common.subsystem.sftp.extensions.AclSupportedParser.AclCapabilities;
import org.apache.sshd.common.subsystem.sftp.extensions.NewlineParser.Newline;
import org.apache.sshd.common.subsystem.sftp.extensions.ParserUtils;
import org.apache.sshd.common.subsystem.sftp.extensions.Supported2Parser.Supported2;
import org.apache.sshd.common.subsystem.sftp.extensions.SupportedParser.Supported;
import org.apache.sshd.common.subsystem.sftp.extensions.VersionsParser.Versions;
import org.apache.sshd.common.subsystem.sftp.extensions.openssh.AbstractOpenSSHExtensionParser.OpenSSHExtension;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.subsystem.sftp.AbstractSftpEventListenerAdapter;
import org.apache.sshd.server.subsystem.sftp.DirectoryHandle;
import org.apache.sshd.server.subsystem.sftp.FileHandle;
import org.apache.sshd.server.subsystem.sftp.Handle;
import org.apache.sshd.server.subsystem.sftp.SftpEventListener;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystem;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystemFactory;
import org.apache.sshd.util.test.JSchLogger;
import org.apache.sshd.util.test.SimpleUserInfo;
import org.apache.sshd.util.test.Utils;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SftpTest extends AbstractSftpClientTestSupport {
    private static final Map<String, OptionalFeature> EXPECTED_EXTENSIONS = SftpSubsystem.DEFAULT_SUPPORTED_CLIENT_EXTENSIONS;

    private com.jcraft.jsch.Session session;

    public SftpTest() throws IOException {
        super();
    }

    @BeforeClass
    public static void jschInit() {
        JSchLogger.init();
    }

    @Before
    public void setUp() throws Exception {
        setupServer();
        JSch sch = new JSch();
        session = sch.getSession("sshd", TEST_LOCALHOST, port);
        session.setUserInfo(new SimpleUserInfo("sshd"));
        session.connect();
    }

    @After
    public void tearDown() throws Exception {
        if (session != null) {
            session.disconnect();
        }

        tearDownServer();
    }

    @Test   // see SSHD-547
    public void testWriteOffsetIgnoredForAppendMode() throws IOException {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.txt");
        Files.deleteIfExists(testFile);

        byte[] expectedRandom = new byte[Byte.MAX_VALUE];
        Factory<? extends Random> factory = sshd.getRandomFactory();
        Random rnd = factory.create();
        rnd.fill(expectedRandom);

        byte[] expectedText = (getClass().getName() + "#" + getCurrentTestName()).getBytes(StandardCharsets.UTF_8);
        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (SftpClient sftp = session.createSftpClient()) {
                    String file = Utils.resolveRelativeRemotePath(parentPath, testFile);

                    try (CloseableHandle handle = sftp.open(file, OpenMode.Create, OpenMode.Write, OpenMode.Read, OpenMode.Append)) {
                        sftp.write(handle, 7365L, expectedRandom);
                        byte[] actualRandom = new byte[expectedRandom.length];
                        int readLen = sftp.read(handle, 0L, actualRandom);
                        assertEquals("Incomplete random data read", expectedRandom.length, readLen);
                        assertArrayEquals("Mismatched read random data", expectedRandom, actualRandom);

                        sftp.write(handle, 3777347L, expectedText);
                        byte[] actualText = new byte[expectedText.length];
                        readLen = sftp.read(handle, actualRandom.length, actualText);
                        assertEquals("Incomplete text data read", actualText.length, readLen);
                        assertArrayEquals("Mismatched read text data", expectedText, actualText);
                    }
                }
            } finally {
                client.stop();
            }
        }

        byte[] actualBytes = Files.readAllBytes(testFile);
        assertEquals("Mismatched result file size", expectedRandom.length + expectedText.length, actualBytes.length);

        byte[] actualRandom = Arrays.copyOfRange(actualBytes, 0, expectedRandom.length);
        assertArrayEquals("Mismatched random part", expectedRandom, actualRandom);

        byte[] actualText = Arrays.copyOfRange(actualBytes, expectedRandom.length, actualBytes.length);
        assertArrayEquals("Mismatched text part", expectedText, actualText);
    }

    @Test   // see SSHD-545
    public void testReadBufferLimit() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.txt");
        byte[] expected = new byte[1024];

        Factory<? extends Random> factory = sshd.getRandomFactory();
        Random rnd = factory.create();
        rnd.fill(expected);
        Files.write(testFile, expected);

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (SftpClient sftp = session.createSftpClient()) {
                    String file = Utils.resolveRelativeRemotePath(parentPath, testFile);
                    byte[] actual = new byte[expected.length];
                    int maxAllowed = actual.length / 4;
                    // allow less than actual
                    PropertyResolverUtils.updateProperty(sshd, SftpSubsystem.MAX_PACKET_LENGTH_PROP, maxAllowed);
                    try (CloseableHandle handle = sftp.open(file, OpenMode.Read)) {
                        int readLen = sftp.read(handle, 0L, actual);
                        assertEquals("Mismatched read len", maxAllowed, readLen);

                        for (int index = 0; index < readLen; index++) {
                            byte expByte = expected[index];
                            byte actByte = actual[index];
                            if (expByte != actByte) {
                                fail("Mismatched values at index=" + index
                                    + ": expected=0x" + Integer.toHexString(expByte & 0xFF)
                                    + ", actual=0x" + Integer.toHexString(actByte & 0xFF));
                            }
                        }
                    }
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test   // see extra fix for SSHD-538
    public void testNavigateBeyondRootFolder() throws Exception {
        Path rootLocation = Paths.get(OsUtils.isUNIX() ? "/" : "C:\\");
        final FileSystem fsRoot = rootLocation.getFileSystem();
        sshd.setFileSystemFactory(new FileSystemFactory() {
                @Override
                public FileSystem createFileSystem(Session session) throws IOException {
                    return fsRoot;
                }
            });

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (SftpClient sftp = session.createSftpClient()) {
                    String rootDir = sftp.canonicalPath("/");
                    String upDir = sftp.canonicalPath(rootDir + "/..");
                    assertEquals("Mismatched root dir parent", rootDir, upDir);
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test   // see SSHD-605
    public void testCannotEscapeUserAbsoluteRoot() throws Exception {
        testCannotEscapeRoot(true);
    }

    @Test   // see SSHD-605
    public void testCannotEscapeUserRelativeRoot() throws Exception {
        testCannotEscapeRoot(false);
    }

    private void testCannotEscapeRoot(boolean useAbsolutePath) throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        assertHierarchyTargetFolderExists(lclSftp);
        sshd.setFileSystemFactory(new VirtualFileSystemFactory(lclSftp));

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                String escapePath;
                if (useAbsolutePath) {
                    escapePath = targetPath.toString();
                    if (OsUtils.isWin32()) {
                        escapePath = "/" + escapePath.replace(File.separatorChar, '/');
                    }
                } else {
                    Path parent = lclSftp.getParent();
                    Path forbidden = Files.createDirectories(parent.resolve("forbidden"));
                    escapePath = "../" + forbidden.getFileName();
                }

                try (SftpClient sftp = session.createSftpClient()) {
                    SftpClient.Attributes attrs = sftp.stat(escapePath);
                    fail("Unexpected escape success for path=" + escapePath + ": " + attrs);
                } catch (SftpException e) {
                    int expected = OsUtils.isWin32() || (!useAbsolutePath)
                            ? SftpConstants.SSH_FX_INVALID_FILENAME
                            : SftpConstants.SSH_FX_NO_SUCH_FILE;
                    assertEquals("Mismatched status for " + escapePath,
                                 SftpConstants.getStatusName(expected),
                                 SftpConstants.getStatusName(e.getStatus()));
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testNormalizeRemoteRootValues() throws Exception {
        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (SftpClient sftp = session.createSftpClient()) {
                    StringBuilder sb = new StringBuilder(Long.SIZE + 1);
                    String expected = sftp.canonicalPath("/");
                    for (int i = 0; i < Long.SIZE; i++) {
                        if (sb.length() > 0) {
                            sb.setLength(0);
                        }

                        for (int j = 1; j <= i; j++) {
                            sb.append('/');
                        }

                        String remotePath = sb.toString();
                        String actual = sftp.canonicalPath(remotePath);
                        assertEquals("Mismatched roots for " + remotePath.length() + " slashes", expected, actual);
                    }
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testNormalizeRemotePathsValues() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.txt");
        String file = Utils.resolveRelativeRemotePath(parentPath, testFile);
        String[] comps = GenericUtils.split(file, '/');

        try (SshClient client = setupTestClient()) {
            client.start();

            Factory<? extends Random> factory = client.getRandomFactory();
            Random rnd = factory.create();
            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (SftpClient sftp = session.createSftpClient()) {
                    StringBuilder sb = new StringBuilder(file.length() + comps.length);
                    String expected = sftp.canonicalPath(file);
                    for (int i = 0; i < file.length(); i++) {
                        if (sb.length() > 0) {
                            sb.setLength(0);
                        }

                        sb.append(comps[0]);
                        for (int j = 1; j < comps.length; j++) {
                            String name = comps[j];
                            slashify(sb, rnd);
                            sb.append(name);
                        }
                        slashify(sb, rnd);

                        if (rnd.random(Byte.SIZE) < (Byte.SIZE / 2)) {
                            sb.append('.');
                        }

                        String remotePath = sb.toString();
                        String actual = sftp.canonicalPath(remotePath);
                        assertEquals("Mismatched canonical value for " + remotePath, expected, actual);
                    }
                }
            } finally {
                client.stop();
            }
        }
    }

    private static int slashify(StringBuilder sb, Random rnd) {
        int slashes = 1 /* at least one slash */ + rnd.random(Byte.SIZE);
        for (int k = 0; k < slashes; k++) {
            sb.append('/');
        }

        return slashes;
    }

    @Test
    public void testOpen() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Path clientFolder = lclSftp.resolve("client");
        Path testFile = clientFolder.resolve("file.txt");
        String file = Utils.resolveRelativeRemotePath(parentPath, testFile);

        File javaFile = testFile.toFile();
        assertHierarchyTargetFolderExists(javaFile.getParentFile());

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                javaFile.createNewFile();
                javaFile.setWritable(false, false);
                javaFile.setReadable(false, false);

                try (SftpClient sftp = session.createSftpClient()) {
                    boolean isWindows = OsUtils.isWin32();

                    try (SftpClient.CloseableHandle h = sftp.open(file /* no mode == read */)) {
                        // NOTE: on Windows files are always readable
                        // see https://svn.apache.org/repos/asf/harmony/enhanced/java/branches/java6/classlib/modules/
                        //      luni/src/test/api/windows/org/apache/harmony/luni/tests/java/io/WinFileTest.java
                        assertTrue("Empty read should have failed on " + file, isWindows);
                    } catch (IOException e) {
                        if (isWindows) {
                            throw e;
                        }
                    }

                    try (SftpClient.CloseableHandle h = sftp.open(file, EnumSet.of(SftpClient.OpenMode.Write))) {
                        fail("Empty write should have failed on " + file);
                    } catch (IOException e) {
                        // ok
                    }

                    try (SftpClient.CloseableHandle h = sftp.open(file, EnumSet.of(SftpClient.OpenMode.Truncate))) {
                        // NOTE: on Windows files are always readable
                        assertTrue("Empty truncate should have failed on " + file, isWindows);
                    } catch (IOException e) {
                        // ok
                    }

                    // NOTE: on Windows files are always readable
                    int perms = sftp.stat(file).getPermissions();
                    int readMask = isWindows ? 0 : SftpConstants.S_IRUSR;
                    int permsMask = SftpConstants.S_IWUSR | readMask;
                    assertEquals("Mismatched permissions for " + file + ": 0x" + Integer.toHexString(perms), 0, perms & permsMask);

                    javaFile.setWritable(true, false);

                    try (SftpClient.CloseableHandle h = sftp.open(file, EnumSet.of(SftpClient.OpenMode.Truncate, SftpClient.OpenMode.Write))) {
                        // OK should succeed
                        assertTrue("Handle not marked as open for file=" + file, h.isOpen());
                    }

                    byte[] d = "0123456789\n".getBytes(StandardCharsets.UTF_8);
                    try (SftpClient.CloseableHandle h = sftp.open(file, EnumSet.of(SftpClient.OpenMode.Write))) {
                        sftp.write(h, 0, d, 0, d.length);
                        sftp.write(h, d.length, d, 0, d.length);
                    }

                    try (SftpClient.CloseableHandle h = sftp.open(file, EnumSet.of(SftpClient.OpenMode.Write))) {
                        sftp.write(h, d.length * 2, d, 0, d.length);
                    }

                    try (SftpClient.CloseableHandle h = sftp.open(file, EnumSet.of(SftpClient.OpenMode.Write))) {
                        byte[] overwrite = "-".getBytes(StandardCharsets.UTF_8);
                        sftp.write(h, 3L, overwrite, 0, 1);
                        d[3] = overwrite[0];
                    }

                    try (SftpClient.CloseableHandle h = sftp.open(file /* no mode == read */)) {
                        // NOTE: on Windows files are always readable
                        assertTrue("Data read should have failed on " + file, isWindows);
                    } catch (IOException e) {
                        if (isWindows) {
                            throw e;
                        }
                    }

                    javaFile.setReadable(true, false);

                    byte[] buf = new byte[3];
                    try (SftpClient.CloseableHandle h = sftp.open(file /* no mode == read */)) {
                        int l = sftp.read(h, 2L, buf, 0, buf.length);
                        String expected = new String(d, 2, l, StandardCharsets.UTF_8);
                        String actual = new String(buf, 0, l, StandardCharsets.UTF_8);
                        assertEquals("Mismatched read data", expected, actual);
                    }
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test
    @SuppressWarnings({"checkstyle:anoninnerlength", "checkstyle:methodlength"})
    public void testClient() throws Exception {
        List<NamedFactory<Command>> factories = sshd.getSubsystemFactories();
        assertEquals("Mismatched subsystem factories count", 1, GenericUtils.size(factories));

        NamedFactory<Command> f = factories.get(0);
        assertObjectInstanceOf("Not an SFTP subsystem factory", SftpSubsystemFactory.class, f);

        SftpSubsystemFactory factory = (SftpSubsystemFactory) f;
        final AtomicInteger versionHolder = new AtomicInteger(-1);
        final AtomicInteger openCount = new AtomicInteger(0);
        final AtomicInteger closeCount = new AtomicInteger(0);
        final AtomicLong readSize = new AtomicLong(0L);
        final AtomicLong writeSize = new AtomicLong(0L);
        final AtomicInteger entriesCount = new AtomicInteger(0);
        final AtomicInteger creatingCount = new AtomicInteger(0);
        final AtomicInteger createdCount = new AtomicInteger(0);
        final AtomicInteger removingCount = new AtomicInteger(0);
        final AtomicInteger removedCount = new AtomicInteger(0);
        final AtomicInteger modifyingCount = new AtomicInteger(0);
        final AtomicInteger modifiedCount = new AtomicInteger(0);

        factory.addSftpEventListener(new SftpEventListener() {
            private final Logger log = LoggerFactory.getLogger(SftpEventListener.class);

            @Override
            public void initialized(ServerSession session, int version) {
                log.info("initialized(" + session + ") version: " + version);
                assertTrue("Initialized version below minimum", version >= SftpSubsystem.LOWER_SFTP_IMPL);
                assertTrue("Initialized version above maximum", version <= SftpSubsystem.HIGHER_SFTP_IMPL);
                assertTrue("Initializion re-called", versionHolder.getAndSet(version) < 0);
            }

            @Override
            public void destroying(ServerSession session) {
                log.info("destroying(" + session + ")");
                assertTrue("Initialization method not called", versionHolder.get() > 0);
            }

            @Override
            public void write(ServerSession session, String remoteHandle, FileHandle localHandle, long offset, byte[] data, int dataOffset, int dataLen) {
                writeSize.addAndGet(dataLen);
                if (log.isDebugEnabled()) {
                    log.debug("write(" + session + ")[" + localHandle.getFile() + "] offset=" + offset + ", requested=" + dataLen);
                }
            }

            @Override
            public void removing(ServerSession session, Path path) {
                removingCount.incrementAndGet();
                log.info("removing(" + session + ") " + path);
            }

            @Override
            public void removed(ServerSession session, Path path, Throwable thrown) {
                removedCount.incrementAndGet();
                log.info("removed(" + session + ") " + path
                       + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
            }

            @Override
            public void modifyingAttributes(ServerSession session, Path path, Map<String, ?> attrs) {
                modifyingCount.incrementAndGet();
                log.info("modifyingAttributes(" + session + ") " + path);
            }

            @Override
            public void modifiedAttributes(ServerSession session, Path path, Map<String, ?> attrs, Throwable thrown) {
                modifiedCount.incrementAndGet();
                log.info("modifiedAttributes(" + session + ") " + path
                       + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
            }

            @Override
            public void read(ServerSession session, String remoteHandle, FileHandle localHandle, long offset, byte[] data, int dataOffset, int dataLen, int readLen) {
                readSize.addAndGet(readLen);
                if (log.isDebugEnabled()) {
                    log.debug("read(" + session + ")[" + localHandle.getFile() + "] offset=" + offset + ", requested=" + dataLen + ", read=" + readLen);
                }
            }

            @Override
            public void read(ServerSession session, String remoteHandle, DirectoryHandle localHandle, Map<String, Path> entries) {
                int numEntries = GenericUtils.size(entries);
                entriesCount.addAndGet(numEntries);

                if (log.isDebugEnabled()) {
                    log.debug("read(" + session + ")[" + localHandle.getFile() + "] " + numEntries + " entries");
                }

                if ((numEntries > 0) && log.isTraceEnabled()) {
                    for (Map.Entry<String, Path> ee : entries.entrySet()) {
                        log.trace("read(" + session + ")[" + localHandle.getFile() + "] " + ee.getKey() + " - " + ee.getValue());
                    }
                }
            }

            @Override
            public void open(ServerSession session, String remoteHandle, Handle localHandle) {
                Path path = localHandle.getFile();
                log.info("open(" + session + ")[" + remoteHandle + "] " + (Files.isDirectory(path) ? "directory" : "file") + " " + path);
                openCount.incrementAndGet();
            }

            @Override
            public void moving(ServerSession session, Path srcPath, Path dstPath, Collection<CopyOption> opts) {
                log.info("moving(" + session + ")[" + opts + "]" + srcPath + " => " + dstPath);
            }

            @Override
            public void moved(ServerSession session, Path srcPath, Path dstPath, Collection<CopyOption> opts, Throwable thrown) {
                log.info("moved(" + session + ")[" + opts + "]" + srcPath + " => " + dstPath
                       + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
            }

            @Override
            public void linking(ServerSession session, Path src, Path target, boolean symLink) {
                log.info("linking(" + session + ")[" + symLink + "]" + src + " => " + target);
            }

            @Override
            public void linked(ServerSession session, Path src, Path target, boolean symLink, Throwable thrown) {
                log.info("linked(" + session + ")[" + symLink + "]" + src + " => " + target
                      + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
            }

            @Override
            public void creating(ServerSession session, Path path, Map<String, ?> attrs) {
                creatingCount.incrementAndGet();
                log.info("creating(" + session + ") " + (Files.isDirectory(path) ? "directory" : "file") + " " + path);
            }

            @Override
            public void created(ServerSession session, Path path, Map<String, ?> attrs, Throwable thrown) {
                createdCount.incrementAndGet();
                log.info("created(" + session + ") " + (Files.isDirectory(path) ? "directory" : "file") + " " + path
                       + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
            }

            @Override
            public void blocking(ServerSession session, String remoteHandle, FileHandle localHandle, long offset, long length, int mask) {
                log.info("blocking(" + session + ")[" + localHandle.getFile() + "]"
                       + " offset=" + offset + ", length=" + length + ", mask=0x" + Integer.toHexString(mask));
            }

            @Override
            public void blocked(ServerSession session, String remoteHandle, FileHandle localHandle,
                                long offset, long length, int mask, Throwable thrown) {
                log.info("blocked(" + session + ")[" + localHandle.getFile() + "]"
                       + " offset=" + offset + ", length=" + length + ", mask=0x" + Integer.toHexString(mask)
                       + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
            }

            @Override
            public void unblocking(ServerSession session, String remoteHandle, FileHandle localHandle, long offset, long length) {
                log.info("unblocking(" + session + ")[" + localHandle.getFile() + "] offset=" + offset + ", length=" + length);
            }

            @Override
            public void unblocked(ServerSession session, String remoteHandle, FileHandle localHandle,
                                  long offset, long length, Boolean result, Throwable thrown) {
                log.info("unblocked(" + session + ")[" + localHandle.getFile() + "]"
                       + " offset=" + offset + ", length=" + length + ", result=" + result
                       + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
            }

            @Override
            public void close(ServerSession session, String remoteHandle, Handle localHandle) {
                Path path = localHandle.getFile();
                log.info("close(" + session + ")[" + remoteHandle + "] " + (Files.isDirectory(path) ? "directory" : "file") + " " + path);
                closeCount.incrementAndGet();
            }
        });

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (SftpClient sftp = session.createSftpClient()) {
                    assertEquals("Mismatched negotiated version", sftp.getVersion(), versionHolder.get());
                    testClient(client, sftp);
                }

                assertEquals("Mismatched open/close count", openCount.get(), closeCount.get());
                assertTrue("No entries read", entriesCount.get() > 0);
                assertTrue("No data read", readSize.get() > 0L);
                assertTrue("No data written", writeSize.get() > 0L);
                assertEquals("Mismatched removal counts", removingCount.get(), removedCount.get());
                assertTrue("No removals signalled", removedCount.get() > 0);
                assertEquals("Mismatched creation counts", creatingCount.get(), createdCount.get());
                assertTrue("No creations signalled", creatingCount.get() > 0);
                assertEquals("Mismatched modification counts", modifyingCount.get(), modifiedCount.get());
                assertTrue("No modifications signalled", modifiedCount.get() > 0);
            } finally {
                client.stop();
            }
        }
    }

    /**
     * this test is meant to test out write's logic, to ensure that internal chunking (based on Buffer.MAX_LEN) is
     * functioning properly. To do this, we write a variety of file sizes, both smaller and larger than Buffer.MAX_LEN.
     * in addition, this test ensures that improper arguments passed in get caught with an IllegalArgumentException
     *
     * @throws Exception upon any uncaught exception or failure
     */
    @Test
    public void testWriteChunking() throws Exception {
        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                Path targetPath = detectTargetFolder();
                Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
                Utils.deleteRecursive(lclSftp);

                Path parentPath = targetPath.getParent();
                Path clientFolder = assertHierarchyTargetFolderExists(lclSftp).resolve("client");
                String dir = Utils.resolveRelativeRemotePath(parentPath, clientFolder);

                try (SftpClient sftp = session.createSftpClient()) {
                    sftp.mkdir(dir);

                    uploadAndVerifyFile(sftp, clientFolder, dir, 0, "emptyFile.txt");
                    uploadAndVerifyFile(sftp, clientFolder, dir, 1000, "smallFile.txt");
                    uploadAndVerifyFile(sftp, clientFolder, dir, ByteArrayBuffer.MAX_LEN - 1, "bufferMaxLenMinusOneFile.txt");
                    uploadAndVerifyFile(sftp, clientFolder, dir, ByteArrayBuffer.MAX_LEN, "bufferMaxLenFile.txt");
                    // were chunking not implemented, these would fail. these sizes should invoke our internal chunking mechanism
                    uploadAndVerifyFile(sftp, clientFolder, dir, ByteArrayBuffer.MAX_LEN + 1, "bufferMaxLenPlusOneFile.txt");
                    uploadAndVerifyFile(sftp, clientFolder, dir, (int) (1.5 * ByteArrayBuffer.MAX_LEN), "1point5BufferMaxLenFile.txt");
                    uploadAndVerifyFile(sftp, clientFolder, dir, (2 * ByteArrayBuffer.MAX_LEN) - 1, "2TimesBufferMaxLenMinusOneFile.txt");
                    uploadAndVerifyFile(sftp, clientFolder, dir, 2 * ByteArrayBuffer.MAX_LEN, "2TimesBufferMaxLenFile.txt");
                    uploadAndVerifyFile(sftp, clientFolder, dir, (2 * ByteArrayBuffer.MAX_LEN) + 1, "2TimesBufferMaxLenPlusOneFile.txt");
                    uploadAndVerifyFile(sftp, clientFolder, dir, 200000, "largerFile.txt");

                    // test erroneous calls that check for negative values
                    Path invalidPath = clientFolder.resolve(getCurrentTestName() + "-invalid");
                    testInvalidParams(sftp, invalidPath, Utils.resolveRelativeRemotePath(parentPath, invalidPath));

                    // cleanup
                    sftp.rmdir(dir);
                }
            } finally {
                client.stop();
            }
        }
    }

    private void testInvalidParams(SftpClient sftp, Path file, String filePath) throws Exception {
        // generate random file and upload it
        String randomData = randomString(5);
        byte[] randomBytes = randomData.getBytes(StandardCharsets.UTF_8);
        try (SftpClient.CloseableHandle handle = sftp.open(filePath, EnumSet.of(SftpClient.OpenMode.Write, SftpClient.OpenMode.Create))) {
            try {
                sftp.write(handle, -1, randomBytes, 0, 0);
                fail("should not have been able to write file with invalid file offset for " + filePath);
            } catch (IllegalArgumentException e) {
                // expected
            }
            try {
                sftp.write(handle, 0, randomBytes, -1, 0);
                fail("should not have been able to write file with invalid source offset for " + filePath);
            } catch (IllegalArgumentException e) {
                // expected
            }
            try {
                sftp.write(handle, 0, randomBytes, 0, -1);
                fail("should not have been able to write file with invalid length for " + filePath);
            } catch (IllegalArgumentException e) {
                // expected
            }
            try {
                sftp.write(handle, 0, randomBytes, 0, randomBytes.length + 1);
                fail("should not have been able to write file with length bigger than array itself (no offset) for " + filePath);
            } catch (IllegalArgumentException e) {
                // expected
            }
            try {
                sftp.write(handle, 0, randomBytes, randomBytes.length, 1);
                fail("should not have been able to write file with length bigger than array itself (with offset) for " + filePath);
            } catch (IllegalArgumentException e) {
                // expected
            }
        }

        sftp.remove(filePath);
        assertFalse("File should not be there: " + file.toString(), Files.exists(file));
    }

    private void uploadAndVerifyFile(SftpClient sftp, Path clientFolder, String remoteDir, int size, String filename) throws Exception {
        // generate random file and upload it
        String remotePath = remoteDir + "/" + filename;
        String randomData = randomString(size);
        try (SftpClient.CloseableHandle handle = sftp.open(remotePath, EnumSet.of(SftpClient.OpenMode.Write, SftpClient.OpenMode.Create))) {
            sftp.write(handle, 0, randomData.getBytes(StandardCharsets.UTF_8), 0, randomData.length());
        }

        // verify results
        Path resultPath = clientFolder.resolve(filename);
        assertTrue("File should exist on disk: " + resultPath, Files.exists(resultPath));
        assertTrue("Mismatched file contents: " + resultPath, randomData.equals(readFile(remotePath)));

        // cleanup
        sftp.remove(remotePath);
        assertFalse("File should have been removed: " + resultPath, Files.exists(resultPath));
    }

    @Test
    public void testSftp() throws Exception {
        String d = getCurrentTestName() + "\n";

        Path targetPath = detectTargetFolder();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Utils.deleteRecursive(lclSftp);

        Path target = assertHierarchyTargetFolderExists(lclSftp).resolve("file.txt");
        String remotePath = Utils.resolveRelativeRemotePath(targetPath.getParent(), target);

        final int numIterations = 10;
        StringBuilder sb = new StringBuilder(d.length() * numIterations * numIterations);
        for (int j = 1; j <= numIterations; j++) {
            if (sb.length() > 0) {
                sb.setLength(0);
            }

            for (int i = 0; i < j; i++) {
                sb.append(d);
            }

            sendFile(remotePath, sb.toString());
            assertFileLength(target, sb.length(), TimeUnit.SECONDS.toMillis(5L));
            Files.delete(target);
        }
    }

    @Test
    public void testReadWriteWithOffset() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Utils.deleteRecursive(lclSftp);

        Path localPath = assertHierarchyTargetFolderExists(lclSftp).resolve("file.txt");
        String remotePath = Utils.resolveRelativeRemotePath(targetPath.getParent(), localPath);
        String data = getCurrentTestName();
        String extraData = "@" + getClass().getSimpleName();
        int appendOffset = -5;

        ChannelSftp c = (ChannelSftp) session.openChannel(SftpConstants.SFTP_SUBSYSTEM_NAME);
        c.connect();
        try {
            c.put(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)), remotePath);

            assertTrue("Remote file not created after initial write: " + localPath, Files.exists(localPath));
            assertEquals("Mismatched data read from " + remotePath, data, readFile(remotePath));

            try (OutputStream os = c.put(remotePath, null, ChannelSftp.APPEND, appendOffset)) {
                os.write(extraData.getBytes(StandardCharsets.UTF_8));
            }
        } finally {
            c.disconnect();
        }

        assertTrue("Remote file not created after data update: " + localPath, Files.exists(localPath));

        String expected = data.substring(0, data.length() + appendOffset) + extraData;
        String actual = readFile(remotePath);
        assertEquals("Mismatched final file data in " + remotePath, expected, actual);
    }

    @Test
    public void testReadDir() throws Exception {
        ChannelSftp c = (ChannelSftp) session.openChannel(SftpConstants.SFTP_SUBSYSTEM_NAME);
        c.connect();
        try {
            URI url = getClass().getClassLoader().getResource(SshClient.class.getName().replace('.', '/') + ".class").toURI();
            URI base = new File(System.getProperty("user.dir")).getAbsoluteFile().toURI();
            File baseDir = new File(base.relativize(url).getPath());
            String path = baseDir.getParent() + "/";
            path = path.replace('\\', '/');

            Vector<?> res = c.ls(path);
            File dir = baseDir.getParentFile();
            Collection<String> expNames = OsUtils.isUNIX()
                                        ? new LinkedList<String>()
                                        : new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
            String[] names = dir.list();
            if (GenericUtils.length(names) > 0) {
                for (String n : names) {
                    if (".".equals(n) || "..".equals(n)) {
                        continue;
                    }

                    assertTrue("Failed to accumulate " + n, expNames.add(n));
                }
            }

            for (Object f : res) {
                outputDebugMessage("LsEntry: %s", f);

                ChannelSftp.LsEntry entry = (ChannelSftp.LsEntry) f;
                String name = entry.getFilename();
                if (".".equals(name) || "..".equals(name)) {
                    continue;
                }

                assertTrue("Entry not found: " + name, expNames.remove(name));
            }

            assertTrue("Un-listed names: " + expNames, GenericUtils.isEmpty(expNames));
        } finally {
            c.disconnect();
        }
    }

    @Test
    public void testRename() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Utils.deleteRecursive(lclSftp);

        Path parentPath = targetPath.getParent();
        Path clientFolder = assertHierarchyTargetFolderExists(lclSftp.resolve("client"));

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (SftpClient sftp = session.createSftpClient()) {
                    Path file1 = clientFolder.resolve("file-1.txt");
                    String file1Path = Utils.resolveRelativeRemotePath(parentPath, file1);
                    try (OutputStream os = sftp.write(file1Path, SftpClient.MIN_WRITE_BUFFER_SIZE)) {
                        os.write((getCurrentTestName() + "\n").getBytes(StandardCharsets.UTF_8));
                    }

                    Path file2 = clientFolder.resolve("file-2.txt");
                    String file2Path = Utils.resolveRelativeRemotePath(parentPath, file2);
                    Path file3 = clientFolder.resolve("file-3.txt");
                    String file3Path = Utils.resolveRelativeRemotePath(parentPath, file3);
                    try {
                        sftp.rename(file2Path, file3Path);
                        fail("Unxpected rename success of " + file2Path + " => " + file3Path);
                    } catch (org.apache.sshd.common.subsystem.sftp.SftpException e) {
                        assertEquals("Mismatched status for failed rename of " + file2Path + " => " + file3Path, SftpConstants.SSH_FX_NO_SUCH_FILE, e.getStatus());
                    }

                    try (OutputStream os = sftp.write(file2Path, SftpClient.MIN_WRITE_BUFFER_SIZE)) {
                        os.write("h".getBytes(StandardCharsets.UTF_8));
                    }

                    try {
                        sftp.rename(file1Path, file2Path);
                        fail("Unxpected rename success of " + file1Path + " => " + file2Path);
                    } catch (org.apache.sshd.common.subsystem.sftp.SftpException e) {
                        assertEquals("Mismatched status for failed rename of " + file1Path + " => " + file2Path, SftpConstants.SSH_FX_FILE_ALREADY_EXISTS, e.getStatus());
                    }

                    sftp.rename(file1Path, file2Path, SftpClient.CopyMode.Overwrite);
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testServerExtensionsDeclarations() throws Exception {
        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (SftpClient sftp = session.createSftpClient()) {
                    Map<String, byte[]> extensions = sftp.getServerExtensions();
                    for (String name : new String[]{
                        SftpConstants.EXT_NEWLINE, SftpConstants.EXT_VERSIONS,
                        SftpConstants.EXT_VENDOR_ID, SftpConstants.EXT_ACL_SUPPORTED,
                        SftpConstants.EXT_SUPPORTED, SftpConstants.EXT_SUPPORTED2
                    }) {
                        assertTrue("Missing extension=" + name, extensions.containsKey(name));
                    }

                    Map<String, ?> data = ParserUtils.parse(extensions);
                    for (Map.Entry<String, ?> de : data.entrySet()) {
                        String extName = de.getKey();
                        Object extValue = de.getValue();
                        outputDebugMessage("%s: %s", extName, extValue);
                        if (SftpConstants.EXT_SUPPORTED.equalsIgnoreCase(extName)) {
                            assertSupportedExtensions(extName, ((Supported) extValue).extensionNames);
                        } else if (SftpConstants.EXT_SUPPORTED2.equalsIgnoreCase(extName)) {
                            assertSupportedExtensions(extName, ((Supported2) extValue).extensionNames);
                        } else if (SftpConstants.EXT_ACL_SUPPORTED.equalsIgnoreCase(extName)) {
                            assertSupportedAclCapabilities((AclCapabilities) extValue);
                        } else if (SftpConstants.EXT_VERSIONS.equalsIgnoreCase(extName)) {
                            assertSupportedVersions((Versions) extValue);
                        } else if (SftpConstants.EXT_NEWLINE.equalsIgnoreCase(extName)) {
                            assertNewlineValue((Newline) extValue);
                        }
                    }

                    for (String extName : extensions.keySet()) {
                        if (!data.containsKey(extName)) {
                            outputDebugMessage("No parser for extension=%s", extName);
                        }
                    }

                    for (OpenSSHExtension expected : SftpSubsystem.DEFAULT_OPEN_SSH_EXTENSIONS) {
                        String name = expected.getName();
                        Object value = data.get(name);
                        assertNotNull("OpenSSH extension not declared: " + name, value);

                        OpenSSHExtension actual = (OpenSSHExtension) value;
                        assertEquals("Mismatched version for OpenSSH extension=" + name, expected.getVersion(), actual.getVersion());
                    }

                    for (BuiltinSftpClientExtensions type : BuiltinSftpClientExtensions.VALUES) {
                        String extensionName = type.getName();
                        boolean isOpenSSHExtension = extensionName.endsWith("@openssh.com");
                        SftpClientExtension instance = sftp.getExtension(extensionName);

                        assertNotNull("Extension not implemented:" + extensionName, instance);
                        assertEquals("Mismatched instance name", extensionName, instance.getName());

                        if (instance.isSupported()) {
                            if (isOpenSSHExtension) {
                                assertTrue("Unlisted default OpenSSH extension: " + extensionName, SftpSubsystem.DEFAULT_OPEN_SSH_EXTENSIONS_NAMES.contains(extensionName));
                            }
                        } else {
                            assertTrue("Unsupported non-OpenSSH extension: " + extensionName, isOpenSSHExtension);
                            assertFalse("Unsupported default OpenSSH extension: " + extensionName, SftpSubsystem.DEFAULT_OPEN_SSH_EXTENSIONS_NAMES.contains(extensionName));
                        }
                    }
                }
            } finally {
                client.stop();
            }
        }
    }

    private static void assertSupportedExtensions(String extName, Collection<String> extensionNames) {
        assertEquals(extName + "[count]", EXPECTED_EXTENSIONS.size(), GenericUtils.size(extensionNames));

        for (Map.Entry<String, OptionalFeature> ee : EXPECTED_EXTENSIONS.entrySet()) {
            String name = ee.getKey();
            OptionalFeature f = ee.getValue();
            if (!f.isSupported()) {
                assertFalse(extName + " - unsupported feature reported: " + name, extensionNames.contains(name));
            } else {
                assertTrue(extName + " - missing " + name, extensionNames.contains(name));
            }
        }
    }

    private static void assertSupportedVersions(Versions vers) {
        List<String> values = vers.getVersions();
        assertEquals("Mismatched reported versions size: " + values,
                     1 + SftpSubsystem.HIGHER_SFTP_IMPL - SftpSubsystem.LOWER_SFTP_IMPL,
                     GenericUtils.size(values));
        for (int expected = SftpSubsystem.LOWER_SFTP_IMPL, index = 0; expected <= SftpSubsystem.HIGHER_SFTP_IMPL; expected++, index++) {
            String e = Integer.toString(expected);
            String a = values.get(index);
            assertEquals("Missing value at index=" + index + ": " + values, e, a);
        }
    }

    private static void assertNewlineValue(Newline nl) {
        assertEquals("Mismatched NL value",
                     BufferUtils.toHex(':', IoUtils.EOL.getBytes(StandardCharsets.UTF_8)),
                     BufferUtils.toHex(':', nl.getNewline().getBytes(StandardCharsets.UTF_8)));
    }

    private static void assertSupportedAclCapabilities(AclCapabilities caps) {
        Set<Integer> actual = AclCapabilities.deconstructAclCapabilities(caps.getCapabilities());
        assertEquals("Mismatched ACL capabilities count", SftpSubsystem.DEFAULT_ACL_SUPPORTED_MASK.size(), actual.size());
        assertTrue("Missing capabilities - expected=" + SftpSubsystem.DEFAULT_ACL_SUPPORTED_MASK + ", actual=" + actual,
                   actual.containsAll(SftpSubsystem.DEFAULT_ACL_SUPPORTED_MASK));
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

                try (SftpClient sftp = session.createSftpClient(selector)) {
                    assertEquals("Mismatched negotiated version", selected.get(), sftp.getVersion());
                    testClient(client, sftp);
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test   // see SSHD-621
    public void testServerDoesNotSupportSftp() throws Exception {
        sshd.setSubsystemFactories(null);

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                PropertyResolverUtils.updateProperty(session, SftpClient.SFTP_CHANNEL_OPEN_TIMEOUT, TimeUnit.SECONDS.toMillis(4L));
                try (SftpClient sftp = session.createSftpClient()) {
                    fail("Unexpected SFTP client creation success");
                } catch (SocketTimeoutException | EOFException | WindowClosedException e) {
                    // expected - ignored
                }
            } finally {
                client.stop();
            }
        }
    }

    private void testClient(FactoryManager manager, SftpClient sftp) throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Utils.deleteRecursive(lclSftp);

        Path parentPath = targetPath.getParent();
        Path clientFolder = assertHierarchyTargetFolderExists(lclSftp).resolve("client");
        String dir = Utils.resolveRelativeRemotePath(parentPath, clientFolder);
        String file = dir + "/" + "file.txt";

        sftp.mkdir(dir);

        try (SftpClient.CloseableHandle h = sftp.open(file, EnumSet.of(SftpClient.OpenMode.Write, SftpClient.OpenMode.Create))) {
            byte[] d = "0123456789\n".getBytes(StandardCharsets.UTF_8);
            sftp.write(h, 0, d, 0, d.length);
            sftp.write(h, d.length, d, 0, d.length);

            SftpClient.Attributes attrs = sftp.stat(h);
            assertNotNull("No handle attributes", attrs);
        }

        try (SftpClient.CloseableHandle h = sftp.openDir(dir)) {
            List<SftpClient.DirEntry> dirEntries = sftp.readDir(h);
            assertNotNull("No dir entries", dirEntries);

            boolean dotFiltered = false;
            boolean dotdotFiltered = false;
            for (Iterator<SftpClient.DirEntry> it = dirEntries.iterator(); it.hasNext();) {
                SftpClient.DirEntry entry = it.next();
                String name = entry.getFilename();
                if (".".equals(name) && (!dotFiltered)) {
                    it.remove();
                    dotFiltered = true;
                } else if ("..".equals(name) && (!dotdotFiltered)) {
                    it.remove();
                    dotdotFiltered = true;
                }
            }

            assertTrue("Dot entry not listed", dotFiltered);
            assertTrue("Dot-dot entry not listed", dotdotFiltered);
            assertEquals("Mismatched number of listed entries", 1, dirEntries.size());
            assertNull("Unexpected extra entry read after listing ended", sftp.readDir(h));
        }

        sftp.remove(file);

        final int sizeFactor = Short.SIZE;
        byte[] workBuf = new byte[IoUtils.DEFAULT_COPY_SIZE * Short.SIZE];
        Factory<? extends Random> factory = manager.getRandomFactory();
        Random random = factory.create();
        random.fill(workBuf);

        try (OutputStream os = sftp.write(file)) {
            os.write(workBuf);
        }

        // force several internal read cycles to satisfy the full read
        try (InputStream is = sftp.read(file, workBuf.length / sizeFactor)) {
            int readLen = is.read(workBuf);
            assertEquals("Mismatched read data length", workBuf.length, readLen);

            int i = is.read();
            assertEquals("Unexpected read past EOF", -1, i);
        }

        SftpClient.Attributes attributes = sftp.stat(file);
        assertTrue("Test file not detected as regular", attributes.isRegularFile());

        attributes = sftp.stat(dir);
        assertTrue("Test directory not reported as such", attributes.isDirectory());

        int nb = 0;
        boolean dotFiltered = false;
        boolean dotdotFiltered = false;
        for (SftpClient.DirEntry entry : sftp.readDir(dir)) {
            assertNotNull("Unexpected null entry", entry);
            String name = entry.getFilename();
            if (".".equals(name) && (!dotFiltered)) {
                dotFiltered = true;
            } else if ("..".equals(name) && (!dotdotFiltered)) {
                dotdotFiltered = true;
            } else {
                nb++;
            }
        }
        assertTrue("Dot entry not read", dotFiltered);
        assertTrue("Dot-dot entry not read", dotdotFiltered);
        assertEquals("Mismatched read dir entries", 1, nb);

        sftp.remove(file);

        sftp.rmdir(dir);
    }

    @Test
    public void testCreateSymbolicLink() throws Exception {
        // Do not execute on windows as the file system does not support symlinks
        Assume.assumeTrue("Skip non-Unix O/S", OsUtils.isUNIX());
        List<NamedFactory<Command>> factories = sshd.getSubsystemFactories();
        assertEquals("Mismatched subsystem factories count", 1, GenericUtils.size(factories));

        NamedFactory<Command> f = factories.get(0);
        assertObjectInstanceOf("Not an SFTP subsystem factory", SftpSubsystemFactory.class, f);

        SftpSubsystemFactory factory = (SftpSubsystemFactory) f;
        final AtomicReference<LinkData> linkDataHolder = new AtomicReference<>();
        factory.addSftpEventListener(new AbstractSftpEventListenerAdapter() {
            @Override
            public void linking(ServerSession session, Path src, Path target, boolean symLink) {
                assertNull("Multiple linking calls", linkDataHolder.getAndSet(new LinkData(src, target, symLink)));
            }

            @Override
            public void linked(ServerSession session, Path src, Path target, boolean symLink, Throwable thrown) {
                LinkData data = linkDataHolder.get();
                assertNotNull("No previous linking call", data);
                assertSame("Mismatched source", data.getSource(), src);
                assertSame("Mismatched target", data.getTarget(), target);
                assertEquals("Mismatched link type", data.isSymLink(), symLink);
                assertNull("Unexpected failure", thrown);
            }
        });

        Path targetPath = detectTargetFolder();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Utils.deleteRecursive(lclSftp);

        /*
         * NOTE !!! according to Jsch documentation
         * (see http://epaul.github.io/jsch-documentation/simple.javadoc/com/jcraft/jsch/ChannelSftp.html#current-directory)
         *
         *
         *         This sftp client has the concept of a current local directory and
         *         a current remote directory. These are not inherent to the protocol,
         *      but are used implicitly for all path-based commands sent to the server
         *      for the remote directory) or accessing the local file system (for the local directory).
         *
         *  Therefore we are using "absolute" remote files for this test
         */
        Path parentPath = targetPath.getParent();
        Path sourcePath = assertHierarchyTargetFolderExists(lclSftp).resolve("src.txt");
        String remSrcPath = "/" + Utils.resolveRelativeRemotePath(parentPath, sourcePath);

        String data = getCurrentTestName();
        ChannelSftp c = (ChannelSftp) session.openChannel(SftpConstants.SFTP_SUBSYSTEM_NAME);
        c.connect();
        try {
            try (InputStream dataStream = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8))) {
                c.put(dataStream, remSrcPath);
            }
            assertTrue("Source file not created: " + sourcePath, Files.exists(sourcePath));
            assertEquals("Mismatched stored data in " + remSrcPath, data, readFile(remSrcPath));

            Path linkPath = lclSftp.resolve("link-" + sourcePath.getFileName());
            String remLinkPath = "/" + Utils.resolveRelativeRemotePath(parentPath, linkPath);
            LinkOption[] options = IoUtils.getLinkOptions(false);
            if (Files.exists(linkPath, options)) {
                Files.delete(linkPath);
            }
            assertFalse("Target link exists before linking: " + linkPath, Files.exists(linkPath, options));

            outputDebugMessage("Symlink %s => %s", remLinkPath, remSrcPath);
            c.symlink(remSrcPath, remLinkPath);

            assertTrue("Symlink not created: " + linkPath, Files.exists(linkPath, options));
            assertEquals("Mismatched link data in " + remLinkPath, data, readFile(remLinkPath));

            String str1 = c.readlink(remLinkPath);
            String str2 = c.realpath(remSrcPath);
            assertEquals("Mismatched link vs. real path", str1, str2);
        } finally {
            c.disconnect();
        }

        assertNotNull("No symlink signalled", linkDataHolder.getAndSet(null));
    }

    protected String readFile(String path) throws Exception {
        ChannelSftp c = (ChannelSftp) session.openChannel(SftpConstants.SFTP_SUBSYSTEM_NAME);
        c.connect();

        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             InputStream is = c.get(path)) {

            byte[] buffer = new byte[256];
            int count;
            while (-1 != (count = is.read(buffer))) {
                bos.write(buffer, 0, count);
            }

            return bos.toString();
        } finally {
            c.disconnect();
        }
    }

    protected void sendFile(String path, String data) throws Exception {
        ChannelSftp c = (ChannelSftp) session.openChannel(SftpConstants.SFTP_SUBSYSTEM_NAME);
        c.connect();
        try {
            c.put(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)), path);
        } finally {
            c.disconnect();
        }
    }

    private String randomString(int size) {
        StringBuilder sb = new StringBuilder(size);
        for (int i = 0; i < size; i++) {
            sb.append((char) ((i % 10) + '0'));
        }
        return sb.toString();
    }

    static class LinkData {
        private final Path source;
        private final Path target;
        private final boolean symLink;

        LinkData(Path src, Path target, boolean symLink) {
            this.source = ValidateUtils.checkNotNull(src, "No source");
            this.target = ValidateUtils.checkNotNull(target, "No target");
            this.symLink = symLink;
        }

        public Path getSource() {
            return source;
        }

        public Path getTarget() {
            return target;
        }

        public boolean isSymLink() {
            return symLink;
        }

        @Override
        public String toString() {
            return (isSymLink() ? "Symbolic" : "Hard") + " " + getSource() + " => " + getTarget();
        }
    }
}
