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
package org.apache.sshd.sftp.client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.Vector;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.WindowClosedException;
import org.apache.sshd.common.channel.exception.SshChannelClosedException;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.subsystem.SubsystemFactory;
import org.apache.sshd.sftp.SftpModuleProperties;
import org.apache.sshd.sftp.client.SftpClient.Attributes;
import org.apache.sshd.sftp.client.SftpClient.CloseableHandle;
import org.apache.sshd.sftp.client.SftpClient.DirEntry;
import org.apache.sshd.sftp.client.SftpClient.OpenMode;
import org.apache.sshd.sftp.client.extensions.BuiltinSftpClientExtensions;
import org.apache.sshd.sftp.client.extensions.SftpClientExtension;
import org.apache.sshd.sftp.client.impl.DefaultCloseableHandle;
import org.apache.sshd.sftp.client.impl.SftpOutputStreamAsync;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpException;
import org.apache.sshd.sftp.common.extensions.AclSupportedParser.AclCapabilities;
import org.apache.sshd.sftp.common.extensions.NewlineParser.Newline;
import org.apache.sshd.sftp.common.extensions.ParserUtils;
import org.apache.sshd.sftp.common.extensions.Supported2Parser.Supported2;
import org.apache.sshd.sftp.common.extensions.SupportedParser.Supported;
import org.apache.sshd.sftp.common.extensions.VersionsParser.Versions;
import org.apache.sshd.sftp.common.extensions.openssh.AbstractOpenSSHExtensionParser.OpenSSHExtension;
import org.apache.sshd.sftp.server.AbstractSftpEventListenerAdapter;
import org.apache.sshd.sftp.server.AbstractSftpSubsystemHelper;
import org.apache.sshd.sftp.server.DirectoryHandle;
import org.apache.sshd.sftp.server.FileHandle;
import org.apache.sshd.sftp.server.Handle;
import org.apache.sshd.sftp.server.SftpEventListener;
import org.apache.sshd.sftp.server.SftpFileSystemAccessor;
import org.apache.sshd.sftp.server.SftpSubsystemEnvironment;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.apache.sshd.sftp.server.SftpSubsystemProxy;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.SimpleUserInfo;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@SuppressWarnings("checkstyle:MethodCount")
public class SftpTest extends AbstractSftpClientTestSupport {
    private static final Map<String, OptionalFeature> EXPECTED_EXTENSIONS
            = AbstractSftpSubsystemHelper.DEFAULT_SUPPORTED_CLIENT_EXTENSIONS;

    private com.jcraft.jsch.Session session;

    public SftpTest() throws IOException {
        super();
    }

    @Before
    public void setUp() throws Exception {
        setupServer();

        Map<String, Object> props = sshd.getProperties();
        Object forced = props.remove(SftpModuleProperties.SFTP_VERSION.getName());
        if (forced != null) {
            outputDebugMessage("Removed forced version=%s", forced);
        }

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
    }

    @Test // see SSHD-547
    public void testWriteOffsetIgnoredForAppendMode() throws IOException {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.txt");
        Files.deleteIfExists(testFile);

        byte[] expectedRandom = new byte[Byte.MAX_VALUE];
        Factory<? extends Random> factory = sshd.getRandomFactory();
        Random rnd = factory.create();
        rnd.fill(expectedRandom);

        byte[] expectedText = (getClass().getName() + "#" + getCurrentTestName()).getBytes(StandardCharsets.UTF_8);
        String file = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, testFile);
        try (SftpClient sftp = createSingleSessionClient();
             CloseableHandle handle = sftp.open(
                     file, OpenMode.Create, OpenMode.Write, OpenMode.Read, OpenMode.Append)) {
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

        byte[] actualBytes = Files.readAllBytes(testFile);
        assertEquals("Mismatched result file size",
                expectedRandom.length + expectedText.length, actualBytes.length);

        byte[] actualRandom = Arrays.copyOfRange(actualBytes, 0, expectedRandom.length);
        assertArrayEquals("Mismatched random part", expectedRandom, actualRandom);

        byte[] actualText = Arrays.copyOfRange(actualBytes, expectedRandom.length, actualBytes.length);
        assertArrayEquals("Mismatched text part", expectedText, actualText);
    }

    @Test // see SSHD-545
    public void testReadBufferLimit() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.txt");
        byte[] expected = new byte[1024];

        Factory<? extends Random> factory = sshd.getRandomFactory();
        Random rnd = factory.create();
        rnd.fill(expected);
        Files.write(testFile, expected);

        String file = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, testFile);
        byte[] actual = new byte[expected.length];
        int maxAllowed = actual.length / 4;
        // allow less than actual
        SftpModuleProperties.MAX_READDATA_PACKET_LENGTH.set(sshd, maxAllowed);
        try (SftpClient sftp = createSingleSessionClient();
             CloseableHandle handle = sftp.open(file, OpenMode.Read)) {
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
        } finally {
            SftpModuleProperties.MAX_READDATA_PACKET_LENGTH.remove(sshd);
        }
    }

    @Test // see extra fix for SSHD-538
    public void testNavigateBeyondRootFolder() throws Exception {
        Path rootLocation = Paths.get(OsUtils.isUNIX() ? "/" : "C:\\");
        FileSystem fsRoot = rootLocation.getFileSystem();
        sshd.setFileSystemFactory(new FileSystemFactory() {
            @Override
            public Path getUserHomeDir(SessionContext session) throws IOException {
                return rootLocation;
            }

            @Override
            public FileSystem createFileSystem(SessionContext session) throws IOException {
                return fsRoot;
            }
        });

        try (SftpClient sftp = createSingleSessionClient()) {
            String rootDir = sftp.canonicalPath("/");
            String upDir = sftp.canonicalPath(rootDir + "/..");
            assertEquals("Mismatched root dir parent", rootDir, upDir);
        }
    }

    @Test // see SSHD-605
    public void testCannotEscapeUserAbsoluteRoot() throws Exception {
        testCannotEscapeRoot(true);
    }

    @Test // see SSHD-605
    public void testCannotEscapeUserRelativeRoot() throws Exception {
        testCannotEscapeRoot(false);
    }

    private void testCannotEscapeRoot(boolean useAbsolutePath) throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        lclSftp = assertHierarchyTargetFolderExists(lclSftp);
        sshd.setFileSystemFactory(new VirtualFileSystemFactory(lclSftp));

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

        try (SftpClient sftp = createSingleSessionClient()) {
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
    }

    @Test
    public void testNormalizeRemoteRootValues() throws Exception {
        try (SftpClient sftp = createSingleSessionClient()) {
            String expected = sftp.canonicalPath("/");
            StringBuilder sb = new StringBuilder(Long.SIZE + 1);
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
    }

    @Test
    public void testNormalizeRemotePathsValues() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.txt");
        String file = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, testFile);
        String[] comps = GenericUtils.split(file, '/');

        Factory<? extends Random> factory = client.getRandomFactory();
        Random rnd = factory.create();
        try (SftpClient sftp = createSingleSessionClient()) {
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
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Path clientFolder = lclSftp.resolve("client");
        Path testFile = clientFolder.resolve("file.txt");
        String file = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, testFile);

        File javaFile = testFile.toFile();
        assertHierarchyTargetFolderExists(javaFile.getParentFile());

        javaFile.createNewFile();
        javaFile.setWritable(false, false);
        javaFile.setReadable(false, false);
        try (SftpClient sftp = createSingleSessionClient()) {
            boolean isWindows = OsUtils.isWin32();

            try (SftpClient.CloseableHandle h = sftp.open(file /* no mode == read */)) {
                // NOTE: on Windows files are always readable
                // see https://svn.apache.org/repos/asf/harmony/enhanced/java/branches/java6/classlib/modules/
                // luni/src/test/api/windows/org/apache/harmony/luni/tests/java/io/WinFileTest.java
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

            try (SftpClient.CloseableHandle h = sftp.open(
                    file, EnumSet.of(SftpClient.OpenMode.Truncate, SftpClient.OpenMode.Write))) {
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
    }

    @Test // SSHD-899
    public void testNoAttributeImpactOnOpen() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Path clientFolder = lclSftp.resolve("client");
        Path testFile = clientFolder.resolve("file.txt");
        String file = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, testFile);

        assertHierarchyTargetFolderExists(testFile.getParent());
        Files.deleteIfExists(testFile); // make sure starting fresh
        Files.createFile(testFile, IoUtils.EMPTY_FILE_ATTRIBUTES);

        try (SftpClient sftp = createSingleSessionClient()) {
            Collection<PosixFilePermission> initialPermissions = IoUtils.getPermissions(testFile);
            assertTrue("File does not have enough initial permissions: " + initialPermissions,
                    initialPermissions.containsAll(
                            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));

            try (CloseableHandle handle = sendRawAttributeImpactOpen(file, sftp)) {
                outputDebugMessage("%s - handle=%s", getCurrentTestName(), handle);
            }

            Collection<PosixFilePermission> updatedPermissions = IoUtils.getPermissions(testFile);
            assertEquals("Mismatched updated permissions count", initialPermissions.size(), updatedPermissions.size());
            assertTrue("File does not preserve initial permissions: expected=" + initialPermissions + ", actual="
                       + updatedPermissions,
                    updatedPermissions.containsAll(initialPermissions));
        } finally {
            Files.delete(testFile);
        }
    }

    private CloseableHandle sendRawAttributeImpactOpen(String path, SftpClient sftpClient) throws Exception {
        RawSftpClient sftp = assertObjectInstanceOf(
                "Not a raw SFTP client used", RawSftpClient.class, sftpClient);
        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE, false);
        buffer.putString(path, StandardCharsets.UTF_8);
        // access
        buffer.putInt(SftpConstants.ACE4_READ_DATA | SftpConstants.ACE4_READ_ATTRIBUTES);
        // mode
        buffer.putInt(SftpConstants.SSH_FXF_OPEN_EXISTING);
        // flag
        buffer.putInt(SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS);
        buffer.putByte((byte) SftpConstants.SSH_FILEXFER_TYPE_REGULAR);

        buffer.putInt(0);

        int reqId = sftp.send(SftpConstants.SSH_FXP_OPEN, buffer);
        Buffer response = sftp.receive(reqId);
        byte[] rawHandle = getRawFileHandle(response);
        return new DefaultCloseableHandle(sftpClient, path, rawHandle);
    }

    private byte[] getRawFileHandle(Buffer buffer) {
        buffer.getInt(); // length
        int type = buffer.getUByte();
        assertEquals("Mismatched response type", SftpConstants.SSH_FXP_HANDLE, type);
        buffer.getInt(); // id
        return ValidateUtils.checkNotNullAndNotEmpty(
                buffer.getBytes(), "Null/empty handle in buffer", GenericUtils.EMPTY_OBJECT_ARRAY);
    }

    @Test
    public void testInputStreamSkipAndReset() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path localFile = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Files.createDirectories(localFile.getParent());
        byte[] data
                = (getClass().getName() + "#" + getCurrentTestName() + "[" + localFile + "]").getBytes(StandardCharsets.UTF_8);
        Files.write(localFile, data, StandardOpenOption.CREATE);
        try (SftpClient sftp = createSingleSessionClient();
             InputStream stream = sftp.read(
                     CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, localFile), OpenMode.Read)) {
            byte[] expected = new byte[data.length / 4];
            int readLen = expected.length;
            System.arraycopy(data, 0, expected, 0, readLen);

            byte[] actual = new byte[readLen];
            readLen = stream.read(actual);
            assertEquals("Failed to read fully reset data", actual.length, readLen);
            assertArrayEquals("Mismatched re-read data contents", expected, actual);

            System.arraycopy(data, 0, expected, 0, expected.length);
            assertArrayEquals("Mismatched original data contents", expected, actual);

            long skipped = stream.skip(readLen);
            assertEquals("Mismatched skipped forward size", readLen, skipped);

            readLen = stream.read(actual);
            assertEquals("Failed to read fully skipped forward data", actual.length, readLen);

            System.arraycopy(data, expected.length + readLen, expected, 0, expected.length);
            assertArrayEquals("Mismatched skipped forward data contents", expected, actual);
        }
    }

    @Test
    public void testSftpFileSystemAccessor() throws Exception {
        List<SubsystemFactory> factories = sshd.getSubsystemFactories();
        assertEquals("Mismatched subsystem factories count", 1, GenericUtils.size(factories));

        SubsystemFactory f = factories.get(0);
        assertObjectInstanceOf("Not an SFTP subsystem factory", SftpSubsystemFactory.class, f);

        SftpSubsystemFactory factory = (SftpSubsystemFactory) f;
        SftpFileSystemAccessor accessor = factory.getFileSystemAccessor();
        try {
            AtomicReference<Path> fileHolder = new AtomicReference<>();
            AtomicReference<Path> dirHolder = new AtomicReference<>();
            factory.setFileSystemAccessor(new SftpFileSystemAccessor() {
                @Override
                public SeekableByteChannel openFile(
                        ServerSession session, SftpSubsystemProxy subsystem, FileHandle fileHandle, Path file,
                        String handle, Set<? extends OpenOption> options, FileAttribute<?>... attrs)
                        throws IOException {
                    fileHolder.set(file);
                    return SftpFileSystemAccessor.super.openFile(
                            session, subsystem, fileHandle, file, handle, options, attrs);
                }

                @Override
                public DirectoryStream<Path> openDirectory(
                        ServerSession session, SftpSubsystemProxy subsystem,
                        DirectoryHandle dirHandle, Path dir, String handle)
                        throws IOException {
                    dirHolder.set(dir);
                    return SftpFileSystemAccessor.super.openDirectory(session, subsystem, dirHandle, dir, handle);
                }

                @Override
                public String toString() {
                    return SftpFileSystemAccessor.class.getSimpleName() + "[" + getCurrentTestName() + "]";
                }
            });

            Path targetPath = detectTargetFolder();
            Path parentPath = targetPath.getParent();
            Path localFile = CommonTestSupportUtils.resolve(
                    targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
            Files.createDirectories(localFile.getParent());
            byte[] expected = (getClass().getName() + "#" + getCurrentTestName() + "[" + localFile + "]")
                    .getBytes(StandardCharsets.UTF_8);
            Files.write(localFile, expected, StandardOpenOption.CREATE);
            try (SftpClient sftp = createSingleSessionClient()) {
                byte[] actual = new byte[expected.length];
                try (InputStream stream = sftp.read(
                        CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, localFile), OpenMode.Read)) {
                    IoUtils.readFully(stream, actual);
                }

                Path remoteFile = fileHolder.getAndSet(null);
                assertNotNull("No remote file holder value", remoteFile);
                assertEquals("Mismatched opened local files", localFile.toFile(), remoteFile.toFile());
                assertArrayEquals("Mismatched retrieved file contents", expected, actual);

                Path localParent = localFile.getParent();
                String localName = Objects.toString(localFile.getFileName(), null);
                try (CloseableHandle handle = sftp.openDir(
                        CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, localParent))) {
                    List<DirEntry> entries = sftp.readDir(handle);
                    Path remoteParent = dirHolder.getAndSet(null);
                    assertNotNull("No remote folder holder value", remoteParent);
                    assertEquals("Mismatched opened folder", localParent.toFile(), remoteParent.toFile());
                    assertFalse("No dir entries", GenericUtils.isEmpty(entries));

                    for (DirEntry de : entries) {
                        Attributes attrs = de.getAttributes();
                        if (!attrs.isRegularFile()) {
                            continue;
                        }

                        if (localName.equals(de.getFilename())) {
                            return;
                        }
                    }

                    fail("Cannot find listing of " + localName);
                }
            }
        } finally {
            factory.setFileSystemAccessor(accessor); // restore original
        }
    }

    @Test
    @SuppressWarnings({ "checkstyle:anoninnerlength", "checkstyle:methodlength" })
    public void testClient() throws Exception {
        List<SubsystemFactory> factories = sshd.getSubsystemFactories();
        assertEquals("Mismatched subsystem factories count", 1, GenericUtils.size(factories));

        SubsystemFactory f = factories.get(0);
        assertObjectInstanceOf("Not an SFTP subsystem factory", SftpSubsystemFactory.class, f);

        SftpSubsystemFactory factory = (SftpSubsystemFactory) f;
        AtomicInteger versionHolder = new AtomicInteger(-1);
        AtomicInteger openCount = new AtomicInteger(0);
        AtomicInteger closeCount = new AtomicInteger(0);
        AtomicLong readSize = new AtomicLong(0L);
        AtomicLong writeSize = new AtomicLong(0L);
        AtomicInteger entriesCount = new AtomicInteger(0);
        AtomicInteger creatingCount = new AtomicInteger(0);
        AtomicInteger createdCount = new AtomicInteger(0);
        AtomicInteger removingFileCount = new AtomicInteger(0);
        AtomicInteger removedFileCount = new AtomicInteger(0);
        AtomicInteger removingDirectoryCount = new AtomicInteger(0);
        AtomicInteger removedDirectoryCount = new AtomicInteger(0);
        AtomicInteger modifyingCount = new AtomicInteger(0);
        AtomicInteger modifiedCount = new AtomicInteger(0);
        SftpEventListener listener = new AbstractSftpEventListenerAdapter() {
            @Override
            public void initialized(ServerSession session, int version) {
                log.info("initialized(" + session + ") version: " + version);
                assertTrue("Initialized version below minimum", version >= SftpSubsystemEnvironment.LOWER_SFTP_IMPL);
                assertTrue("Initialized version above maximum", version <= SftpSubsystemEnvironment.HIGHER_SFTP_IMPL);
                assertTrue("Initializion re-called", versionHolder.getAndSet(version) < 0);
            }

            @Override
            public void destroying(ServerSession session) {
                log.info("destroying(" + session + ")");
                assertTrue("Initialization method not called", versionHolder.get() > 0);
            }

            @Override
            public void written(
                    ServerSession session, String remoteHandle, FileHandle localHandle,
                    long offset, byte[] data, int dataOffset, int dataLen, Throwable thrown) {
                writeSize.addAndGet(dataLen);
                if (log.isDebugEnabled()) {
                    log.debug("write(" + session + ")[" + localHandle.getFile() + "] offset=" + offset + ", requested="
                              + dataLen);
                }
            }

            @Override
            public void removing(ServerSession session, Path path, boolean isDirectory) {
                if (isDirectory) {
                    removingDirectoryCount.incrementAndGet();
                } else {
                    removingFileCount.incrementAndGet();
                }
                log.info("removing(" + session + ")[dir=" + isDirectory + "] " + path);
            }

            @Override
            public void removed(ServerSession session, Path path, boolean isDirectory, Throwable thrown) {
                if (isDirectory) {
                    removedDirectoryCount.incrementAndGet();
                } else {
                    removedFileCount.incrementAndGet();
                }
                log.info("removed(" + session + ")[dir=" + isDirectory + "] " + path
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
            @SuppressWarnings("checkstyle:ParameterNumber")
            public void read(
                    ServerSession session, String remoteHandle, FileHandle localHandle, long offset,
                    byte[] data, int dataOffset, int dataLen, int readLen, Throwable thrown) {
                readSize.addAndGet(readLen);
                if (log.isDebugEnabled()) {
                    log.debug("read(" + session + ")[" + localHandle.getFile() + "] offset=" + offset + ", requested=" + dataLen
                              + ", read=" + readLen);
                }
            }

            @Override
            public void readEntries(
                    ServerSession session, String remoteHandle, DirectoryHandle localHandle, Map<String, Path> entries) {
                int numEntries = GenericUtils.size(entries);
                entriesCount.addAndGet(numEntries);

                if (log.isDebugEnabled()) {
                    log.debug("read(" + session + ")[" + localHandle.getFile() + "] " + numEntries + " entries");
                }

                if ((numEntries > 0) && log.isTraceEnabled()) {
                    entries.forEach((key, value) -> log
                            .trace("read(" + session + ")[" + localHandle.getFile() + "] " + key + " - " + value));
                }
            }

            @Override
            public void open(ServerSession session, String remoteHandle, Handle localHandle) {
                Path path = localHandle.getFile();
                log.info("open(" + session + ")[" + remoteHandle + "] " + (Files.isDirectory(path) ? "directory" : "file") + " "
                         + path);
                openCount.incrementAndGet();
            }

            @Override
            public void moving(ServerSession session, Path srcPath, Path dstPath, Collection<CopyOption> opts) {
                log.info("moving(" + session + ")[" + opts + "]" + srcPath + " => " + dstPath);
            }

            @Override
            public void moved(
                    ServerSession session, Path srcPath, Path dstPath, Collection<CopyOption> opts, Throwable thrown) {
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
            public void blocking(
                    ServerSession session, String remoteHandle, FileHandle localHandle, long offset, long length, int mask) {
                log.info("blocking(" + session + ")[" + localHandle.getFile() + "]"
                         + " offset=" + offset + ", length=" + length + ", mask=0x" + Integer.toHexString(mask));
            }

            @Override
            public void blocked(
                    ServerSession session, String remoteHandle, FileHandle localHandle,
                    long offset, long length, int mask, Throwable thrown) {
                log.info("blocked(" + session + ")[" + localHandle.getFile() + "]"
                         + " offset=" + offset + ", length=" + length + ", mask=0x" + Integer.toHexString(mask)
                         + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
            }

            @Override
            public void unblocking(
                    ServerSession session, String remoteHandle, FileHandle localHandle, long offset, long length) {
                log.info("unblocking(" + session + ")[" + localHandle.getFile() + "] offset=" + offset + ", length=" + length);
            }

            @Override
            public void unblocked(
                    ServerSession session, String remoteHandle, FileHandle localHandle,
                    long offset, long length, Throwable thrown) {
                log.info("unblocked(" + session + ")[" + localHandle.getFile() + "]"
                         + " offset=" + offset + ", length=" + length
                         + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
            }

            @Override
            public void closing(ServerSession session, String remoteHandle, Handle localHandle) {
                Path path = localHandle.getFile();
                log.info("close(" + session + ")[" + remoteHandle + "] " + (Files.isDirectory(path) ? "directory" : "file")
                         + " " + path);
                closeCount.incrementAndGet();
            }
        };
        factory.addSftpEventListener(listener);

        try (SftpClient sftp = createSingleSessionClient()) {
            assertEquals("Mismatched negotiated version", sftp.getVersion(), versionHolder.get());
            testClient(client, sftp);

            assertEquals("Mismatched open/close count", openCount.get(), closeCount.get());
            assertTrue("No entries read", entriesCount.get() > 0);
            assertTrue("No data read", readSize.get() > 0L);
            assertTrue("No data written", writeSize.get() > 0L);
            assertEquals("Mismatched removal counts", removingFileCount.get(), removedFileCount.get());
            assertEquals("Mismatched directory removal counts", removingDirectoryCount.get(), removedDirectoryCount.get());
            assertTrue("No removals signalled", removedFileCount.get() > 0);
            assertEquals("Mismatched creation counts", creatingCount.get(), createdCount.get());
            assertTrue("No creations signalled", creatingCount.get() > 0);
            assertEquals("Mismatched modification counts", modifyingCount.get(), modifiedCount.get());
            assertTrue("No modifications signalled", modifiedCount.get() > 0);
        } finally {
            factory.removeSftpEventListener(listener);
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
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        Path parentPath = targetPath.getParent();
        Path clientFolder = assertHierarchyTargetFolderExists(lclSftp).resolve("client");
        String dir = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, clientFolder);

        try (SftpClient sftp = createSingleSessionClient()) {
            sftp.mkdir(dir);

            uploadAndVerifyFile(sftp, clientFolder, dir, 0, "emptyFile.txt");
            uploadAndVerifyFile(sftp, clientFolder, dir, 1000, "smallFile.txt");

            // Make sure sizes should invoke our internal chunking mechanism
            ClientChannel clientChannel = sftp.getClientChannel();
            SftpModuleProperties.WRITE_CHUNK_SIZE.set(clientChannel,
                    Math.min(SftpClient.IO_BUFFER_SIZE, SftpModuleProperties.WRITE_CHUNK_SIZE.getRequiredDefault())
                                                                     - Byte.MAX_VALUE);

            uploadAndVerifyFile(sftp, clientFolder, dir,
                    SshConstants.SSH_REQUIRED_TOTAL_PACKET_LENGTH_SUPPORT - 1, "bufferMaxLenMinusOneFile.txt");
            uploadAndVerifyFile(sftp, clientFolder, dir,
                    SshConstants.SSH_REQUIRED_TOTAL_PACKET_LENGTH_SUPPORT, "bufferMaxLenFile.txt");
            uploadAndVerifyFile(sftp, clientFolder, dir,
                    SshConstants.SSH_REQUIRED_TOTAL_PACKET_LENGTH_SUPPORT + 1, "bufferMaxLenPlusOneFile.txt");
            uploadAndVerifyFile(sftp, clientFolder, dir,
                    (int) (1.5 * SshConstants.SSH_REQUIRED_TOTAL_PACKET_LENGTH_SUPPORT), "1point5BufferMaxLenFile.txt");
            uploadAndVerifyFile(sftp, clientFolder, dir,
                    (2 * SshConstants.SSH_REQUIRED_TOTAL_PACKET_LENGTH_SUPPORT) - 1, "2TimesBufferMaxLenMinusOneFile.txt");
            uploadAndVerifyFile(sftp, clientFolder, dir,
                    2 * SshConstants.SSH_REQUIRED_TOTAL_PACKET_LENGTH_SUPPORT, "2TimesBufferMaxLenFile.txt");
            uploadAndVerifyFile(sftp, clientFolder, dir,
                    (2 * SshConstants.SSH_REQUIRED_TOTAL_PACKET_LENGTH_SUPPORT) + 1, "2TimesBufferMaxLenPlusOneFile.txt");
            uploadAndVerifyFile(sftp, clientFolder, dir, 200000, "largerFile.txt");

            // test erroneous calls that check for negative values
            Path invalidPath = clientFolder.resolve(getCurrentTestName() + "-invalid");
            testInvalidParams(sftp, invalidPath, CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, invalidPath));

            // cleanup
            sftp.rmdir(dir);
        }
    }

    private void testInvalidParams(SftpClient sftp, Path file, String filePath) throws Exception {
        // generate random file and upload it
        String randomData = randomString(5);
        byte[] randomBytes = randomData.getBytes(StandardCharsets.UTF_8);
        try (SftpClient.CloseableHandle handle = sftp.open(
                filePath, EnumSet.of(SftpClient.OpenMode.Write, SftpClient.OpenMode.Create))) {
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
                fail("should not have been able to write file with length bigger than array itself (no offset) for "
                     + filePath);
            } catch (IllegalArgumentException e) {
                // expected
            }
            try {
                sftp.write(handle, 0, randomBytes, randomBytes.length, 1);
                fail("should not have been able to write file with length bigger than array itself (with offset) for "
                     + filePath);
            } catch (IllegalArgumentException e) {
                // expected
            }
        }

        sftp.remove(filePath);
        assertFalse("File should not be there: " + file.toString(), Files.exists(file));
    }

    private void uploadAndVerifyFile(
            SftpClient sftp, Path clientFolder, String remoteDir, int size, String filename)
            throws Exception {
        // generate random file and upload it
        String remotePath = remoteDir + "/" + filename;
        String randomData = randomString(size);
        try (SftpClient.CloseableHandle handle = sftp.open(
                remotePath, EnumSet.of(SftpClient.OpenMode.Write, SftpClient.OpenMode.Create))) {
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
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        Path target = assertHierarchyTargetFolderExists(lclSftp).resolve("file.txt");
        String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(targetPath.getParent(), target);

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
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        Path localPath = assertHierarchyTargetFolderExists(lclSftp).resolve("file.txt");
        String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(targetPath.getParent(), localPath);
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
        Path cwdPath = Paths.get(System.getProperty("user.dir")).toAbsolutePath();
        Path tgtPath = detectTargetFolder();
        Collection<String> expNames = OsUtils.isUNIX()
                ? new LinkedList<>()
                : new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(tgtPath)) {
            for (Path p : ds) {
                String n = Objects.toString(p.getFileName());
                if (".".equals(n) || "..".equals(n)) {
                    continue;
                }

                assertTrue("Failed to accumulate " + n, expNames.add(n));
            }
        }

        Path baseDir = cwdPath.relativize(tgtPath);
        String path = baseDir + "/";
        path = path.replace('\\', '/');

        ChannelSftp c = (ChannelSftp) session.openChannel(SftpConstants.SFTP_SUBSYSTEM_NAME);
        c.connect();
        try {
            Vector<?> res = c.ls(path);
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
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        Path parentPath = targetPath.getParent();
        Path clientFolder = assertHierarchyTargetFolderExists(lclSftp.resolve("client"));
        try (SftpClient sftp = createSingleSessionClient()) {
            Path file1 = clientFolder.resolve("file-1.txt");
            String file1Path = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, file1);
            try (OutputStream os = sftp.write(file1Path, SftpClient.MIN_WRITE_BUFFER_SIZE)) {
                os.write((getCurrentTestName() + "\n").getBytes(StandardCharsets.UTF_8));
            }

            Path file2 = clientFolder.resolve("file-2.txt");
            String file2Path = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, file2);
            Path file3 = clientFolder.resolve("file-3.txt");
            String file3Path = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, file3);
            try {
                sftp.rename(file2Path, file3Path);
                fail("Unxpected rename success of " + file2Path + " => " + file3Path);
            } catch (SftpException e) {
                assertEquals("Mismatched status for failed rename of " + file2Path + " => " + file3Path,
                        SftpConstants.SSH_FX_NO_SUCH_FILE, e.getStatus());
            }

            try (OutputStream os = sftp.write(file2Path, SftpClient.MIN_WRITE_BUFFER_SIZE)) {
                os.write("h".getBytes(StandardCharsets.UTF_8));
            }

            try {
                sftp.rename(file1Path, file2Path);
                fail("Unxpected rename success of " + file1Path + " => " + file2Path);
            } catch (SftpException e) {
                assertEquals("Mismatched status for failed rename of " + file1Path + " => " + file2Path,
                        SftpConstants.SSH_FX_FILE_ALREADY_EXISTS, e.getStatus());
            }

            sftp.rename(file1Path, file2Path, SftpClient.CopyMode.Overwrite);
        }
    }

    @Test
    public void testServerExtensionsDeclarations() throws Exception {
        try (SftpClient sftp = createSingleSessionClient()) {
            Map<String, byte[]> extensions = sftp.getServerExtensions();
            for (String name : new String[] {
                    SftpConstants.EXT_NEWLINE, SftpConstants.EXT_VERSIONS,
                    SftpConstants.EXT_VENDOR_ID, SftpConstants.EXT_ACL_SUPPORTED,
                    SftpConstants.EXT_SUPPORTED, SftpConstants.EXT_SUPPORTED2
            }) {
                assertTrue("Missing extension=" + name, extensions.containsKey(name));
            }

            Map<String, ?> data = ParserUtils.parse(extensions);
            data.forEach((extName, extValue) -> {
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
            });

            for (String extName : extensions.keySet()) {
                if (!data.containsKey(extName)) {
                    outputDebugMessage("No parser for extension=%s", extName);
                }
            }

            for (OpenSSHExtension expected : AbstractSftpSubsystemHelper.DEFAULT_OPEN_SSH_EXTENSIONS) {
                String name = expected.getName();
                Object value = data.get(name);
                assertNotNull("OpenSSH extension not declared: " + name, value);

                OpenSSHExtension actual = (OpenSSHExtension) value;
                assertEquals("Mismatched version for OpenSSH extension=" + name, expected.getVersion(),
                        actual.getVersion());
            }

            for (BuiltinSftpClientExtensions type : BuiltinSftpClientExtensions.VALUES) {
                String extensionName = type.getName();
                boolean isOpenSSHExtension = extensionName.endsWith("@openssh.com");
                SftpClientExtension instance = sftp.getExtension(extensionName);

                assertNotNull("Extension not implemented:" + extensionName, instance);
                assertEquals("Mismatched instance name", extensionName, instance.getName());

                if (instance.isSupported()) {
                    if (isOpenSSHExtension) {
                        assertTrue("Unlisted default OpenSSH extension: " + extensionName,
                                AbstractSftpSubsystemHelper.DEFAULT_OPEN_SSH_EXTENSIONS_NAMES.contains(extensionName));
                    }
                } else {
                    assertTrue("Unsupported non-OpenSSH extension: " + extensionName, isOpenSSHExtension);
                    assertFalse("Unsupported default OpenSSH extension: " + extensionName,
                            AbstractSftpSubsystemHelper.DEFAULT_OPEN_SSH_EXTENSIONS_NAMES.contains(extensionName));
                }
            }
        }
    }

    private static void assertSupportedExtensions(String extName, Collection<String> extensionNames) {
        assertEquals(extName + "[count]", EXPECTED_EXTENSIONS.size(), GenericUtils.size(extensionNames));

        EXPECTED_EXTENSIONS.forEach((name, f) -> {
            if (!f.isSupported()) {
                assertFalse(extName + " - unsupported feature reported: " + name, extensionNames.contains(name));
            } else {
                assertTrue(extName + " - missing " + name, extensionNames.contains(name));
            }
        });
    }

    private static void assertSupportedVersions(Versions vers) {
        List<String> values = vers.getVersions();
        assertEquals("Mismatched reported versions size: " + values,
                1 + SftpSubsystemEnvironment.HIGHER_SFTP_IMPL - SftpSubsystemEnvironment.LOWER_SFTP_IMPL,
                GenericUtils.size(values));
        for (int expected = SftpSubsystemEnvironment.LOWER_SFTP_IMPL, index = 0;
             expected <= SftpSubsystemEnvironment.HIGHER_SFTP_IMPL;
             expected++, index++) {
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
        assertEquals("Mismatched ACL capabilities count", AbstractSftpSubsystemHelper.DEFAULT_ACL_SUPPORTED_MASK.size(),
                actual.size());
        assertTrue("Missing capabilities - expected=" + AbstractSftpSubsystemHelper.DEFAULT_ACL_SUPPORTED_MASK + ", actual="
                   + actual,
                actual.containsAll(AbstractSftpSubsystemHelper.DEFAULT_ACL_SUPPORTED_MASK));
    }

    @Test
    public void testSftpVersionSelector() throws Exception {
        AtomicInteger selected = new AtomicInteger(-1);
        SftpVersionSelector selector = (session, initial, current, available) -> {
            int value = initial
                    ? current : GenericUtils.stream(available)
                            .mapToInt(Integer::intValue)
                            .filter(v -> v != current)
                            .max()
                            .orElseGet(() -> current);
            selected.set(value);
            return value;
        };

        try (ClientSession session = createAuthenticatedClientSession();
             SftpClient sftp = SftpClientFactory.instance().createSftpClient(session, selector)) {
            assertEquals("Mismatched negotiated version", selected.get(), sftp.getVersion());
            testClient(client, sftp);
        }
    }

    @Test // see SSHD-621
    public void testServerDoesNotSupportSftp() throws Exception {
        List<SubsystemFactory> factories = sshd.getSubsystemFactories();
        assertEquals("Mismatched subsystem factories count", 1, GenericUtils.size(factories));

        sshd.setSubsystemFactories(null);
        try (ClientSession session = createAuthenticatedClientSession()) {
            SftpModuleProperties.SFTP_CHANNEL_OPEN_TIMEOUT.set(session, Duration.ofSeconds(7L));
            try (SftpClient sftp = createSftpClient(session)) {
                fail("Unexpected SFTP client creation success");
            } catch (SocketTimeoutException | EOFException | WindowClosedException | SshChannelClosedException e) {
                // expected - ignored
            } finally {
                SftpModuleProperties.SFTP_CHANNEL_OPEN_TIMEOUT.remove(session);
            }
        } finally {
            sshd.setSubsystemFactories(factories);
        }
    }

    private void testClient(FactoryManager manager, SftpClient sftp) throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        Path parentPath = targetPath.getParent();
        Path clientFolder = assertHierarchyTargetFolderExists(lclSftp).resolve("client");
        String dir = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, clientFolder);
        sftp.mkdir(dir);

        String file = dir + "/" + getCurrentTestName() + "-file.txt";
        try (SftpClient.CloseableHandle h = sftp.open(
                file, EnumSet.of(SftpClient.OpenMode.Write, SftpClient.OpenMode.Create))) {
            byte[] d = "0123456789\n".getBytes(StandardCharsets.UTF_8);
            sftp.write(h, 0, d, 0, d.length);
            sftp.write(h, d.length, d, 0, d.length);

            SftpClient.Attributes attrs = sftp.stat(h);
            assertNotNull("No handle attributes", attrs);
        }

        try (SftpClient.CloseableHandle h = sftp.openDir(dir)) {
            List<SftpClient.DirEntry> dirEntries = new ArrayList<>();
            boolean dotFiltered = false;
            boolean dotdotFiltered = false;
            for (SftpClient.DirEntry entry : sftp.listDir(h)) {
                String name = entry.getFilename();
                outputDebugMessage("readDir(%s) initial file: %s", dir, name);
                if (".".equals(name) && (!dotFiltered)) {
                    dotFiltered = true;
                } else if ("..".equals(name) && (!dotdotFiltered)) {
                    dotdotFiltered = true;
                } else {
                    dirEntries.add(entry);
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
            outputDebugMessage("readDir(%s) overwritten file: %s", dir, name);

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
        List<SubsystemFactory> factories = sshd.getSubsystemFactories();
        assertEquals("Mismatched subsystem factories count", 1, GenericUtils.size(factories));

        SubsystemFactory f = factories.get(0);
        assertObjectInstanceOf("Not an SFTP subsystem factory", SftpSubsystemFactory.class, f);

        SftpSubsystemFactory factory = (SftpSubsystemFactory) f;
        AtomicReference<LinkData> linkDataHolder = new AtomicReference<>();
        SftpEventListener listener = new AbstractSftpEventListenerAdapter() {
            @Override
            public void linking(ServerSession session, Path src, Path target, boolean symLink) {
                assertNull("Multiple linking calls", linkDataHolder.getAndSet(new LinkData(src, target, symLink)));
            }

            @Override
            public void linked(
                    ServerSession session, Path src, Path target, boolean symLink, Throwable thrown) {
                LinkData data = linkDataHolder.get();
                assertNotNull("No previous linking call", data);
                assertSame("Mismatched source", data.getSource(), src);
                assertSame("Mismatched target", data.getTarget(), target);
                assertEquals("Mismatched link type", data.isSymLink(), symLink);
                assertNull("Unexpected failure", thrown);
            }
        };

        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        /*
         * NOTE !!! according to Jsch documentation (see
         * http://epaul.github.io/jsch-documentation/simple.javadoc/com/jcraft/jsch/ChannelSftp.html#current-directory)
         *
         *
         * This sftp client has the concept of a current local directory and a current remote directory. These are not
         * inherent to the protocol, but are used implicitly for all path-based commands sent to the server for the
         * remote directory) or accessing the local file system (for the local directory).
         *
         * Therefore we are using "absolute" remote files for this test
         */
        Path parentPath = targetPath.getParent();
        Path sourcePath = assertHierarchyTargetFolderExists(lclSftp).resolve("src.txt");
        String remSrcPath = "/" + CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, sourcePath);

        factory.addSftpEventListener(listener);
        try {
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
                String remLinkPath = "/" + CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, linkPath);
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
        } finally {
            factory.removeSftpEventListener(listener);
        }

        assertNotNull("No symlink signalled", linkDataHolder.getAndSet(null));
    }

    @Test // see SSHD-903
    public void testForcedVersionNegotiation() throws Exception {
        SftpModuleProperties.SFTP_VERSION.set(sshd, SftpConstants.SFTP_V3);
        try (SftpClient sftp = createSingleSessionClient()) {
            assertEquals("Mismatched negotiated version", SftpConstants.SFTP_V3, sftp.getVersion());
        }
    }

    protected String readFile(String path) throws Exception {
        ChannelSftp c = (ChannelSftp) session.openChannel(SftpConstants.SFTP_SUBSYSTEM_NAME);
        c.connect();

        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             InputStream is = c.get(path)) {
            byte[] buffer = new byte[256];
            for (int count = is.read(buffer); count != -1; count = is.read(buffer)) {
                bos.write(buffer, 0, count);
            }

            return bos.toString(StandardCharsets.UTF_8.name());
        } finally {
            c.disconnect();
        }
    }

    protected void sendFile(String path, String data) throws Exception {
        ChannelSftp c = (ChannelSftp) session.openChannel(SftpConstants.SFTP_SUBSYSTEM_NAME);
        c.connect();
        try (InputStream srcStream = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8))) {
            c.put(srcStream, path);
        } finally {
            c.disconnect();
        }
    }

    private static String randomString(int size) {
        StringBuilder sb = new StringBuilder(size);
        for (int i = 0; i < size; i++) {
            sb.append((char) ((i % 10) + '0'));
        }
        return sb.toString();
    }

    @Test   // see SSHD-1022
    public void testFlushOutputStreamWithoutWrite() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        Path parentPath = targetPath.getParent();
        Path clientFolder = assertHierarchyTargetFolderExists(lclSftp.resolve("client"));
        try (SftpClient sftp = createSingleSessionClient()) {
            Path file = clientFolder.resolve("file.txt");
            String filePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, file);
            try (OutputStream os = sftp.write(filePath, SftpClient.MIN_WRITE_BUFFER_SIZE)) {
                assertObjectInstanceOf(SftpOutputStreamAsync.class.getSimpleName(), SftpOutputStreamAsync.class, os);

                for (int index = 1; index <= 5; index++) {
                    outputDebugMessage("%s - pre write flush attempt #%d", getCurrentTestName(), index);
                    os.flush();
                }

                os.write((getCurrentTestName() + "\n").getBytes(StandardCharsets.UTF_8));

                for (int index = 1; index <= 5; index++) {
                    outputDebugMessage("%s - post write flush attempt #%d", getCurrentTestName(), index);
                    os.flush();
                }
            }
        }
    }

    static class LinkData {
        private final Path source;
        private final Path target;
        private final boolean symLink;

        LinkData(Path src, Path target, boolean symLink) {
            this.source = Objects.requireNonNull(src, "No source");
            this.target = Objects.requireNonNull(target, "No target");
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
