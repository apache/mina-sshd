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
import java.util.HashSet;
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
import org.apache.sshd.common.util.MapEntryUtils;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@SuppressWarnings("checkstyle:MethodCount")
public class SftpTest extends AbstractSftpClientTestSupport {
    private static final Map<String, OptionalFeature> EXPECTED_EXTENSIONS
            = AbstractSftpSubsystemHelper.DEFAULT_SUPPORTED_CLIENT_EXTENSIONS;

    private com.jcraft.jsch.Session session;

    private int sftpHandleSize;

    public void initSftpTest(int handleSize) throws Exception {
        sftpHandleSize = handleSize;
        setUp();
    }

    public static List<Integer> getParameters() {
        List<Integer> result = new ArrayList<>();
        result.add(Integer.valueOf(4));
        result.add(Integer.valueOf(16));
        return result;
    }

    void setUp() throws Exception {
        setupServer();

        Map<String, Object> props = sshd.getProperties();
        Object forced = props.remove(SftpModuleProperties.SFTP_VERSION.getName());
        if (forced != null) {
            outputDebugMessage("Removed forced version=%s", forced);
        }

        SftpModuleProperties.FILE_HANDLE_SIZE.set(sshd, Integer.valueOf(sftpHandleSize));
        JSch sch = new JSch();
        session = sch.getSession("sshd", TEST_LOCALHOST, port);
        session.setUserInfo(new SimpleUserInfo("sshd"));
        session.connect();
    }

    @AfterEach
    void tearDown() throws Exception {
        if (session != null) {
            session.disconnect();
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}") // see SSHD-547
    public void writeOffsetIgnoredForAppendMode(int handleSize) throws Exception {
        initSftpTest(handleSize);
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
            // Read one byte
            byte[] data = new byte[1];
            int readLen = sftp.read(handle, 0L, data);
            assertEquals(1, readLen);
            assertEquals(data[0], expectedRandom[0]);
            // Write more -- should be appended
            sftp.write(handle, 3777347L, expectedText);
            // Read the full random data
            byte[] actualRandom = new byte[expectedRandom.length];
            readLen = sftp.read(handle, 0L, actualRandom);
            assertEquals(expectedRandom.length, readLen, "Incomplete random data read");
            assertArrayEquals(expectedRandom, actualRandom, "Mismatched read random data");

            // Read the data from the second write
            byte[] actualText = new byte[expectedText.length];
            readLen = sftp.read(handle, actualRandom.length, actualText);
            assertEquals(actualText.length, readLen, "Incomplete text data read");
            assertArrayEquals(expectedText, actualText, "Mismatched read text data");
        }

        byte[] actualBytes = Files.readAllBytes(testFile);
        assertEquals(expectedRandom.length + expectedText.length, actualBytes.length, "Mismatched result file size");

        byte[] actualRandom = Arrays.copyOfRange(actualBytes, 0, expectedRandom.length);
        assertArrayEquals(expectedRandom, actualRandom, "Mismatched random part");

        byte[] actualText = Arrays.copyOfRange(actualBytes, expectedRandom.length, actualBytes.length);
        assertArrayEquals(expectedText, actualText, "Mismatched text part");
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}") // see SSHD-545
    public void readBufferLimit(int handleSize) throws Exception {
        initSftpTest(handleSize);
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.bin");
        byte[] expected = new byte[(SftpModuleProperties.MIN_READDATA_PACKET_LENGTH + 16) * 4];

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
            assertEquals(maxAllowed, readLen, "Mismatched read len");

            for (int index = 0; index < readLen; index++) {
                byte expByte = expected[index];
                byte actByte = actual[index];
                assertEquals(Integer.toHexString(expByte & 0xFF),
                        Integer.toHexString(actByte & 0xFF),
                        "Mismatched values at index=" + index);
            }
        } finally {
            SftpModuleProperties.MAX_READDATA_PACKET_LENGTH.remove(sshd);
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}") // see SSHD-1287
    public void readWithLargeBuffer(int handleSize) throws Exception {
        initSftpTest(handleSize);
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.bin");
        byte[] expected = new byte[1024 * 1024];

        Factory<? extends Random> factory = sshd.getRandomFactory();
        Random rnd = factory.create();
        rnd.fill(expected);
        Files.write(testFile, expected);

        String file = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, testFile);
        try (SftpClient sftp = createSingleSessionClient()) {
            byte[] actual = new byte[expected.length];
            try (InputStream in = sftp.read(file,
                    2 * SftpModuleProperties.MAX_READDATA_PACKET_LENGTH.getRequiredDefault() + 2048)) {
                int off = 0;
                int n = 0;
                while (off < actual.length) {
                    n = in.read(actual, off, actual.length - off);
                    if (n < 0) {
                        break;
                    }
                    off += n;
                }
                assertEquals(actual.length, off, "Short read");
                if (n >= 0) {
                    n = in.read();
                    assertTrue(n < 0, "Stream not at eof");
                }
            }
            for (int index = 0; index < actual.length; index++) {
                byte expByte = expected[index];
                byte actByte = actual[index];
                assertEquals(Integer.toHexString(expByte & 0xFF),
                        Integer.toHexString(actByte & 0xFF),
                        "Mismatched values at index=" + index);
            }
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}") // see SSHD-1287
    public void zeroRead(int handleSize) throws Exception {
        initSftpTest(handleSize);
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.bin");
        byte[] expected = new byte[4000];

        Factory<? extends Random> factory = sshd.getRandomFactory();
        Random rnd = factory.create();
        rnd.fill(expected);
        Files.write(testFile, expected);

        String file = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, testFile);
        try (SftpClient sftp = createSingleSessionClient()) {
            byte[] actual = new byte[expected.length];
            try (InputStream in = sftp.read(file)) {
                int off = 0;
                int n = 0;
                while (off < actual.length) {
                    n = in.read(actual, off, 100);
                    if (n < 0) {
                        break;
                    }
                    off += n;
                    if (in.read(actual, off, 0) < 0) {
                        break;
                    }
                }
                assertEquals(actual.length, off, "Short read");
                if (n >= 0) {
                    n = in.read();
                    assertTrue(n < 0, "Stream not at eof");
                }
            }
            for (int index = 0; index < actual.length; index++) {
                byte expByte = expected[index];
                byte actByte = actual[index];
                assertEquals(Integer.toHexString(expByte & 0xFF),
                        Integer.toHexString(actByte & 0xFF),
                        "Mismatched values at index=" + index);
            }
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}") // see SSHD-1288
    public void readWriteDownload(int handleSize) throws Exception {
        initSftpTest(handleSize);
        Assumptions.assumeTrue(OsUtils.isUNIX() || OsUtils.isOSX(),
                "Not sure appending to a file opened for reading works on Windows");
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.bin");
        byte[] expected = new byte[1024 * 1024];

        Factory<? extends Random> factory = sshd.getRandomFactory();
        Random rnd = factory.create();
        rnd.fill(expected);
        Files.write(testFile, expected);

        String file = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, testFile);
        try (SftpClient sftp = createSingleSessionClient()) {
            byte[] actual;
            try (InputStream in = sftp.read(file); ByteArrayOutputStream buf = new ByteArrayOutputStream(2 * expected.length)) {
                Files.write(testFile, expected, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
                byte[] data = new byte[4096];
                for (int n = 0; n >= 0;) {
                    n = in.read(data, 0, data.length);
                    if (n > 0) {
                        buf.write(data, 0, n);
                    }
                }
                actual = buf.toByteArray();
            }
            assertEquals(2 * expected.length, actual.length, "Short read");
            for (int i = 0, j = 0; i < actual.length; i++, j++) {
                if (j >= expected.length) {
                    j = 0;
                }
                byte expByte = expected[j];
                byte actByte = actual[i];
                assertEquals(Integer.toHexString(expByte & 0xFF),
                        Integer.toHexString(actByte & 0xFF),
                        "Mismatched values at index=" + i);
            }
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}") // see GH-774
    public void copyByReadWrite(int handleSize) throws Exception {
        initSftpTest(handleSize);
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.bin");
        // Size matters; with only 1MB GH-774 is not reproducible. Probably the size needs to be larger than the channel
        // window (2MB by default).
        byte[] expected = new byte[8 * 1024 * 1024];

        Factory<? extends Random> factory = sshd.getRandomFactory();
        Random rnd = factory.create();
        rnd.fill(expected);
        Files.write(testFile, expected);

        String file = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, testFile);
        try (SftpClient sftp = createSingleSessionClient()) {
            try (InputStream in = sftp.read(file);
                 OutputStream out = sftp.write(file + ".new", SftpClient.OpenMode.Create, SftpClient.OpenMode.Write)) {
                IoUtils.copy(in, out);
            }
            byte[] actual;
            try (InputStream in = sftp.read(file + ".new");
                 ByteArrayOutputStream buf = new ByteArrayOutputStream(expected.length)) {
                byte[] data = new byte[4096];
                for (int n = 0; n >= 0;) {
                    n = in.read(data, 0, data.length);
                    if (n > 0) {
                        buf.write(data, 0, n);
                    }
                }
                actual = buf.toByteArray();
            }
            assertArrayEquals(expected, actual);
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}")
    public void emptyFileDownload(int handleSize) throws Exception {
        initSftpTest(handleSize);
        Assumptions.assumeTrue(OsUtils.isUNIX() || OsUtils.isOSX(),
                "Not sure appending to a file opened for reading works on Windows");
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.bin");
        byte[] expected = new byte[0];

        Files.write(testFile, expected);

        String file = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, testFile);
        try (SftpClient sftp = createSingleSessionClient()) {
            try (InputStream in = sftp.read(file)) {
                assertEquals(-1, in.read());
            }
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}") // see extra fix for SSHD-538
    public void navigateBeyondRootFolder(int handleSize) throws Exception {
        initSftpTest(handleSize);
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
            assertEquals(rootDir, upDir, "Mismatched root dir parent");
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}") // see SSHD-605
    public void cannotEscapeUserAbsoluteRoot(int handleSize) throws Exception {
        initSftpTest(handleSize);
        testCannotEscapeRoot(true);
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}") // see SSHD-605
    public void cannotEscapeUserRelativeRoot(int handleSize) throws Exception {
        initSftpTest(handleSize);
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
            int expected = OsUtils.isWin32() && useAbsolutePath
                    ? SftpConstants.SSH_FX_INVALID_FILENAME
                    : SftpConstants.SSH_FX_NO_SUCH_FILE;
            assertEquals(SftpConstants.getStatusName(expected),
                    SftpConstants.getStatusName(e.getStatus()),
                    "Mismatched status for " + escapePath);
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}")
    public void normalizeRemoteRootValues(int handleSize) throws Exception {
        initSftpTest(handleSize);
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
                assertEquals(expected, actual, "Mismatched roots for " + remotePath.length() + " slashes");
            }
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}")
    public void normalizeRemotePathsValues(int handleSize) throws Exception {
        initSftpTest(handleSize);
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
                assertEquals(expected, actual, "Mismatched canonical value for " + remotePath);
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

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}")
    public void open(int handleSize) throws Exception {
        initSftpTest(handleSize);
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
                assertTrue(isWindows, "Empty read should have failed on " + file);
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
                assertTrue(isWindows, "Empty truncate should have failed on " + file);
            } catch (IOException e) {
                // ok
            }

            // NOTE: on Windows files are always readable
            int perms = sftp.stat(file).getPermissions();
            int readMask = isWindows ? 0 : SftpConstants.S_IRUSR;
            int permsMask = SftpConstants.S_IWUSR | readMask;
            assertEquals(0, perms & permsMask, "Mismatched permissions for " + file + ": 0x" + Integer.toHexString(perms));

            javaFile.setWritable(true, false);

            try (SftpClient.CloseableHandle h = sftp.open(
                    file, EnumSet.of(SftpClient.OpenMode.Truncate, SftpClient.OpenMode.Write))) {
                // OK should succeed
                assertTrue(h.isOpen(), "Handle not marked as open for file=" + file);
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
                assertTrue(isWindows, "Data read should have failed on " + file);
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
                assertEquals(expected, actual, "Mismatched read data");
            }
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}") // SSHD-899
    public void noAttributeImpactOnOpen(int handleSize) throws Exception {
        initSftpTest(handleSize);
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
            assertTrue(initialPermissions.containsAll(
                    EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)),
                    "File does not have enough initial permissions: " + initialPermissions);

            try (CloseableHandle handle = sendRawAttributeImpactOpen(file, sftp)) {
                outputDebugMessage("%s - handle=%s", getCurrentTestName(), handle);
            }

            Collection<PosixFilePermission> updatedPermissions = IoUtils.getPermissions(testFile);
            assertEquals(initialPermissions.size(), updatedPermissions.size(), "Mismatched updated permissions count");
            assertTrue(updatedPermissions.containsAll(initialPermissions),
                    "File does not preserve initial permissions: expected=" + initialPermissions + ", actual="
                                                                           + updatedPermissions);
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

        buffer.putUInt(0L);

        int reqId = sftp.send(SftpConstants.SSH_FXP_OPEN, buffer);
        Buffer response = sftp.receive(reqId);
        byte[] rawHandle = getRawFileHandle(response);
        return new DefaultCloseableHandle(sftpClient, path, rawHandle);
    }

    private byte[] getRawFileHandle(Buffer buffer) {
        buffer.getUInt(); // length
        int type = buffer.getUByte();
        assertEquals(SftpConstants.SSH_FXP_HANDLE, type, "Mismatched response type");
        buffer.getInt(); // id
        return ValidateUtils.checkNotNullAndNotEmpty(
                buffer.getBytes(), "Null/empty handle in buffer", GenericUtils.EMPTY_OBJECT_ARRAY);
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}")
    public void inputStreamSkipAndReset(int handleSize) throws Exception {
        initSftpTest(handleSize);
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
            assertEquals(actual.length, readLen, "Failed to read fully reset data");
            assertArrayEquals(expected, actual, "Mismatched re-read data contents");

            System.arraycopy(data, 0, expected, 0, expected.length);
            assertArrayEquals(expected, actual, "Mismatched original data contents");

            long skipped = stream.skip(readLen);
            assertEquals(readLen, skipped, "Mismatched skipped forward size");

            readLen = stream.read(actual);
            assertEquals(actual.length, readLen, "Failed to read fully skipped forward data");

            System.arraycopy(data, expected.length + readLen, expected, 0, expected.length);
            assertArrayEquals(expected, actual, "Mismatched skipped forward data contents");
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}") // see SSHD-1182
    public void inputStreamSkipBeforeRead(int handleSize) throws Exception {
        initSftpTest(handleSize);
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
            int toSkip = data.length / 4;
            int readLen = data.length / 2;
            byte[] expected = new byte[readLen];
            byte[] actual = new byte[readLen];

            System.arraycopy(data, toSkip, expected, 0, readLen);

            long skipped = stream.skip(toSkip);
            assertEquals(toSkip, skipped, "Mismatched skipped forward size");

            int actuallyRead = IoUtils.read(stream, actual);
            assertEquals(readLen, actuallyRead, "Failed to read fully skipped forward data");

            assertArrayEquals(expected, actual, "Unexpected data read after skipping");
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}")
    public void sftpFileSystemAccessor(int handleSize) throws Exception {
        initSftpTest(handleSize);
        List<? extends SubsystemFactory> factories = sshd.getSubsystemFactories();
        assertEquals(1, GenericUtils.size(factories), "Mismatched subsystem factories count");

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
                        SftpSubsystemProxy subsystem, FileHandle fileHandle, Path file,
                        String handle, Set<? extends OpenOption> options, FileAttribute<?>... attrs)
                        throws IOException {
                    fileHolder.set(file);
                    return SftpFileSystemAccessor.super.openFile(
                            subsystem, fileHandle, file, handle, options, attrs);
                }

                @Override
                public DirectoryStream<Path> openDirectory(
                        SftpSubsystemProxy subsystem, DirectoryHandle dirHandle, Path dir, String handle,
                        LinkOption... linkOptions)
                        throws IOException {
                    dirHolder.set(dir);
                    return SftpFileSystemAccessor.super.openDirectory(subsystem, dirHandle, dir, handle, linkOptions);
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
                assertNotNull(remoteFile, "No remote file holder value");
                assertEquals(localFile.toFile(), remoteFile.toFile(), "Mismatched opened local files");
                assertArrayEquals(expected, actual, "Mismatched retrieved file contents");

                Path localParent = localFile.getParent();
                String localName = Objects.toString(localFile.getFileName(), null);
                try (CloseableHandle handle = sftp.openDir(
                        CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, localParent))) {
                    List<DirEntry> entries = sftp.readDir(handle);
                    Path remoteParent = dirHolder.getAndSet(null);
                    assertNotNull(remoteParent, "No remote folder holder value");
                    assertEquals(localParent.toFile(), remoteParent.toFile(), "Mismatched opened folder");
                    assertFalse(GenericUtils.isEmpty(entries), "No dir entries");

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

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}")
    @SuppressWarnings({ "checkstyle:anoninnerlength", "checkstyle:methodlength" })
    public void client(int handleSize) throws Exception {
        initSftpTest(handleSize);
        List<? extends SubsystemFactory> factories = sshd.getSubsystemFactories();
        assertEquals(1, GenericUtils.size(factories), "Mismatched subsystem factories count");

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
                assertTrue(version >= SftpSubsystemEnvironment.LOWER_SFTP_IMPL, "Initialized version below minimum");
                assertTrue(version <= SftpSubsystemEnvironment.HIGHER_SFTP_IMPL, "Initialized version above maximum");
                assertTrue(versionHolder.getAndSet(version) < 0, "Initializion re-called");
            }

            @Override
            public void destroying(ServerSession session) {
                log.info("destroying(" + session + ")");
                assertTrue(versionHolder.get() > 0, "Initialization method not called");
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
                int numEntries = MapEntryUtils.size(entries);
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
            assertEquals(sftp.getVersion(), versionHolder.get(), "Mismatched negotiated version");
            testClient(client, sftp);

            assertEquals(openCount.get(), closeCount.get(), "Mismatched open/close count");
            assertTrue(entriesCount.get() > 0, "No entries read");
            assertTrue(readSize.get() > 0L, "No data read");
            assertTrue(writeSize.get() > 0L, "No data written");
            assertEquals(removingFileCount.get(), removedFileCount.get(), "Mismatched removal counts");
            assertEquals(removingDirectoryCount.get(), removedDirectoryCount.get(), "Mismatched directory removal counts");
            assertTrue(removedFileCount.get() > 0, "No removals signalled");
            assertEquals(creatingCount.get(), createdCount.get(), "Mismatched creation counts");
            assertTrue(creatingCount.get() > 0, "No creations signalled");
            assertEquals(modifyingCount.get(), modifiedCount.get(), "Mismatched modification counts");
            assertTrue(modifiedCount.get() > 0, "No modifications signalled");
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
    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}")
    public void writeChunking(int handleSize) throws Exception {
        initSftpTest(handleSize);
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

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}") // SSHD-1215
    public void writeCreateAppend(int handleSize) throws Exception {
        initSftpTest(handleSize);
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        Path parentPath = targetPath.getParent();
        Path clientFolder = assertHierarchyTargetFolderExists(lclSftp).resolve("client");

        String dir = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, clientFolder);

        try (SftpClient sftp = createSingleSessionClient()) {
            sftp.mkdir(dir);

            uploadAndVerifyFile(sftp, clientFolder, dir, 200000, "large.txt",
                    EnumSet.of(SftpClient.OpenMode.Write, SftpClient.OpenMode.Create, SftpClient.OpenMode.Append), "Hello");

            // cleanup
            sftp.rmdir(dir);
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}") // SSHD-1215
    public void listDirWithBlank(int handleSize) throws Exception {
        Assumptions.assumeFalse(OsUtils.isWin32(), "Windows does not allow trailing blanks anyway");
        initSftpTest(handleSize);
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        Path parentPath = targetPath.getParent();
        Path clientFolder = assertHierarchyTargetFolderExists(lclSftp.resolve("withBlank "));
        String fileName = "file ";
        Path clientFile = clientFolder.resolve(fileName);

        byte[] foo = { 'f', 'o', 'o' };
        Files.write(clientFile, foo);

        String dir = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, clientFolder);

        try (SftpClient sftp = createSingleSessionClient()) {
            List<String> expected = new ArrayList<>();
            expected.add(".");
            expected.add("..");
            expected.add(fileName);
            List<String> actual = new ArrayList<>();
            sftp.readDir(dir).iterator().forEachRemaining(e -> actual.add(e.getFilename()));
            assertEquals(expected, actual, "Unexpected directory entries");
            try (InputStream in = sftp.read(dir + '/' + fileName)) {
                assertArrayEquals(foo, IoUtils.toByteArray(in), "Wrong file content");
            }
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}")
    public void handleSize(int handleSize) throws Exception {
        initSftpTest(handleSize);
        List<? extends SubsystemFactory> factories = sshd.getSubsystemFactories();
        assertEquals(1, GenericUtils.size(factories), "Mismatched subsystem factories count");

        SubsystemFactory f = factories.get(0);
        assertObjectInstanceOf("Not an SFTP subsystem factory", SftpSubsystemFactory.class, f);

        SftpSubsystemFactory factory = (SftpSubsystemFactory) f;
        Set<String> handles = new HashSet<>();
        SftpEventListener listener = new AbstractSftpEventListenerAdapter() {

            @Override
            public void open(ServerSession session, String remoteHandle, Handle localHandle) throws IOException {
                handles.add(remoteHandle);
            }
        };
        factory.addSftpEventListener(listener);
        try {
            Path targetPath = detectTargetFolder();
            Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME,
                    getClass().getSimpleName(), getCurrentTestName());
            CommonTestSupportUtils.deleteRecursive(lclSftp);

            Path parentPath = targetPath.getParent();
            Path clientFolder = assertHierarchyTargetFolderExists(lclSftp).resolve("client");

            String dir = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, clientFolder);

            try (SftpClient sftp = createSingleSessionClient()) {
                sftp.mkdir(dir);
                // Write some files
                byte[] data = "something".getBytes(StandardCharsets.US_ASCII);
                try (CloseableHandle handle = sftp.open(dir + "/first.bin", OpenMode.Write, OpenMode.Create)) {
                    assertEquals(handleSize, handle.getIdentifier().length, "Unexpected handle size");
                    sftp.write(handle, 0, data, 0, data.length);
                }
                assertEquals(1, handles.size(), "Unexpected number of handles");
                try (CloseableHandle handle1 = sftp.open(dir + "/second.bin", OpenMode.Write, OpenMode.Create);
                     CloseableHandle handle2 = sftp.open(dir + "/third.bin", OpenMode.Write, OpenMode.Create)) {
                    assertEquals(handleSize, handle1.getIdentifier().length, "Unexpected handle size");
                    assertEquals(handleSize, handle2.getIdentifier().length, "Unexpected handle size");
                    sftp.write(handle1, 0, data, 0, data.length);
                    sftp.write(handle2, 0, data, 0, data.length);
                }
                if (handleSize == Integer.BYTES) {
                    assertEquals(2, handles.size(), "Unexpected number of handles");
                } else {
                    assertTrue(handles.size() <= 3, "Unexpected number of handles");
                }
                try (CloseableHandle handle1 = sftp.open(dir + "/fourth.bin", OpenMode.Write, OpenMode.Create)) {
                    assertEquals(handleSize, handle1.getIdentifier().length, "Unexpected handle size");
                    byte[] id2;
                    try (CloseableHandle handle2 = sftp.open(dir + "/fifth.bin", OpenMode.Write, OpenMode.Create)) {
                        id2 = handle2.getIdentifier();
                        assertEquals(handleSize, id2.length, "Unexpected handle size");
                        sftp.write(handle2, 0, data, 0, data.length);
                    }
                    byte[] id3;
                    try (CloseableHandle handle3 = sftp.open(dir + "/sixth.bin", OpenMode.Write, OpenMode.Create)) {
                        id3 = handle3.getIdentifier();
                        assertEquals(handleSize, id3.length, "Unexpected handle size");
                        if (handleSize == Integer.BYTES) {
                            // Should have been re-used
                            assertArrayEquals(id2, id3, "Expected handles to be the same");
                        }
                        sftp.write(handle3, 0, data, 0, data.length);
                    }
                    sftp.write(handle1, 0, data, 0, data.length);
                }
                assertArrayEquals(data, Files.readAllBytes(clientFolder.resolve("first.bin")), "Unexpected data in first.bin");
                assertArrayEquals(data,
                        Files.readAllBytes(clientFolder.resolve("second.bin")),
                        "Unexpected data in second.bin");
                assertArrayEquals(data, Files.readAllBytes(clientFolder.resolve("third.bin")), "Unexpected data in third.bin");
                assertArrayEquals(data,
                        Files.readAllBytes(clientFolder.resolve("fourth.bin")),
                        "Unexpected data in fourth.bin");
                assertArrayEquals(data, Files.readAllBytes(clientFolder.resolve("fifth.bin")), "Unexpected data in fifth.bin");
                assertArrayEquals(data, Files.readAllBytes(clientFolder.resolve("sixth.bin")), "Unexpected data in sixth.bin");
                if (handleSize == Integer.BYTES) {
                    assertEquals(2, handles.size(), "Unexpected number of handles");
                } else {
                    assertTrue(handles.size() <= 6, "Unexpected number of handles");
                }
            }
        } finally {
            factory.removeSftpEventListener(listener);
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
        assertFalse(Files.exists(file), "File should not be there: " + file.toString());
    }

    private void uploadAndVerifyFile(
            SftpClient sftp, Path clientFolder, String remoteDir, int size, String filename)
            throws Exception {
        uploadAndVerifyFile(sftp, clientFolder, remoteDir, size, filename,
                EnumSet.of(SftpClient.OpenMode.Write, SftpClient.OpenMode.Create), null);
    }

    private void uploadAndVerifyFile(
            SftpClient sftp, Path clientFolder, String remoteDir, int size, String filename,
            EnumSet<SftpClient.OpenMode> modes, String prefixData)
            throws Exception {
        // generate random file and upload it
        String remotePath = remoteDir + "/" + filename;
        String randomData = randomString(size);
        String expectedData = randomData;
        if (prefixData != null && !prefixData.isEmpty()) {
            Path localFile = clientFolder.resolve(filename);
            Files.write(localFile, prefixData.getBytes(StandardCharsets.UTF_8));
            expectedData = prefixData + randomData;
        }
        try (SftpClient.CloseableHandle handle = sftp.open(remotePath, modes)) {
            sftp.write(handle, 0, randomData.getBytes(StandardCharsets.UTF_8), 0, randomData.length());
        }

        // verify results
        Path resultPath = clientFolder.resolve(filename);
        assertTrue(Files.exists(resultPath), "File should exist on disk: " + resultPath);
        assertEquals(expectedData, readFile(remotePath), "Mismatched file contents: " + resultPath);

        // cleanup
        sftp.remove(remotePath);
        assertFalse(Files.exists(resultPath), "File should have been removed: " + resultPath);
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}")
    public void sftp(int handleSize) throws Exception {
        initSftpTest(handleSize);
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

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}")
    public void readWriteWithOffset(int handleSize) throws Exception {
        initSftpTest(handleSize);
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

            assertTrue(Files.exists(localPath), "Remote file not created after initial write: " + localPath);
            assertEquals(data, readFile(remotePath), "Mismatched data read from " + remotePath);

            try (OutputStream os = c.put(remotePath, null, ChannelSftp.APPEND, appendOffset)) {
                os.write(extraData.getBytes(StandardCharsets.UTF_8));
            }
        } finally {
            c.disconnect();
        }

        assertTrue(Files.exists(localPath), "Remote file not created after data update: " + localPath);

        String expected = data.substring(0, data.length() + appendOffset) + extraData;
        String actual = readFile(remotePath);
        assertEquals(expected, actual, "Mismatched final file data in " + remotePath);
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}")
    public void readDir(int handleSize) throws Exception {
        initSftpTest(handleSize);
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

                assertTrue(expNames.add(n), "Failed to accumulate " + n);
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

                assertTrue(expNames.remove(name), "Entry not found: " + name);
            }

            assertTrue(GenericUtils.isEmpty(expNames), "Un-listed names: " + expNames);
        } finally {
            c.disconnect();
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}")
    public void rename(int handleSize) throws Exception {
        initSftpTest(handleSize);
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
                assertEquals(SftpConstants.SSH_FX_NO_SUCH_FILE, e.getStatus(),
                        "Mismatched status for failed rename of " + file2Path + " => " + file3Path);
            }

            try (OutputStream os = sftp.write(file2Path, SftpClient.MIN_WRITE_BUFFER_SIZE)) {
                os.write("h".getBytes(StandardCharsets.UTF_8));
            }

            try {
                sftp.rename(file1Path, file2Path);
                fail("Unxpected rename success of " + file1Path + " => " + file2Path);
            } catch (SftpException e) {
                assertEquals(SftpConstants.SSH_FX_FILE_ALREADY_EXISTS, e.getStatus(),
                        "Mismatched status for failed rename of " + file1Path + " => " + file2Path);
            }

            sftp.rename(file1Path, file2Path, SftpClient.CopyMode.Overwrite);
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}")
    public void serverExtensionsDeclarations(int handleSize) throws Exception {
        initSftpTest(handleSize);
        try (SftpClient sftp = createSingleSessionClient()) {
            Map<String, byte[]> extensions = sftp.getServerExtensions();
            for (String name : new String[] {
                    SftpConstants.EXT_NEWLINE, SftpConstants.EXT_VERSIONS,
                    SftpConstants.EXT_VENDOR_ID, SftpConstants.EXT_ACL_SUPPORTED,
                    SftpConstants.EXT_SUPPORTED, SftpConstants.EXT_SUPPORTED2
            }) {
                assertTrue(extensions.containsKey(name), "Missing extension=" + name);
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
                assertNotNull(value, "OpenSSH extension not declared: " + name);

                OpenSSHExtension actual = (OpenSSHExtension) value;
                assertEquals(expected.getVersion(),
                        actual.getVersion(),
                        "Mismatched version for OpenSSH extension=" + name);
            }

            for (BuiltinSftpClientExtensions type : BuiltinSftpClientExtensions.VALUES) {
                String extensionName = type.getName();
                boolean isOpenSSHExtension = extensionName.endsWith("@openssh.com");
                SftpClientExtension instance = sftp.getExtension(extensionName);

                assertNotNull(instance, "Extension not implemented:" + extensionName);
                assertEquals(extensionName, instance.getName(), "Mismatched instance name");

                if (instance.isSupported()) {
                    if (isOpenSSHExtension) {
                        assertTrue(AbstractSftpSubsystemHelper.DEFAULT_OPEN_SSH_EXTENSIONS_NAMES.contains(extensionName),
                                "Unlisted default OpenSSH extension: " + extensionName);
                    }
                } else {
                    assertTrue(isOpenSSHExtension, "Unsupported non-OpenSSH extension: " + extensionName);
                    assertFalse(AbstractSftpSubsystemHelper.DEFAULT_OPEN_SSH_EXTENSIONS_NAMES.contains(extensionName),
                            "Unsupported default OpenSSH extension: " + extensionName);
                }
            }
        }
    }

    private static void assertSupportedExtensions(String extName, Collection<String> extensionNames) {
        assertEquals(EXPECTED_EXTENSIONS.size(), GenericUtils.size(extensionNames), extName + "[count]");

        EXPECTED_EXTENSIONS.forEach((name, f) -> {
            if (!f.isSupported()) {
                assertFalse(extensionNames.contains(name), extName + " - unsupported feature reported: " + name);
            } else {
                assertTrue(extensionNames.contains(name), extName + " - missing " + name);
            }
        });
    }

    private static void assertSupportedVersions(Versions vers) {
        List<String> values = vers.getVersions();
        assertEquals(1 + SftpSubsystemEnvironment.HIGHER_SFTP_IMPL - SftpSubsystemEnvironment.LOWER_SFTP_IMPL,
                GenericUtils.size(values),
                "Mismatched reported versions size: " + values);
        for (int expected = SftpSubsystemEnvironment.LOWER_SFTP_IMPL, index = 0;
             expected <= SftpSubsystemEnvironment.HIGHER_SFTP_IMPL;
             expected++, index++) {
            String e = Integer.toString(expected);
            String a = values.get(index);
            assertEquals(e, a, "Missing value at index=" + index + ": " + values);
        }
    }

    private static void assertNewlineValue(Newline nl) {
        assertEquals(BufferUtils.toHex(':', IoUtils.EOL.getBytes(StandardCharsets.UTF_8)),
                BufferUtils.toHex(':', nl.getNewline().getBytes(StandardCharsets.UTF_8)),
                "Mismatched NL value");
    }

    private static void assertSupportedAclCapabilities(AclCapabilities caps) {
        Set<Integer> actual = AclCapabilities.deconstructAclCapabilities(caps.getCapabilities());
        assertEquals(AbstractSftpSubsystemHelper.DEFAULT_ACL_SUPPORTED_MASK.size(),
                actual.size(),
                "Mismatched ACL capabilities count");
        assertTrue(actual.containsAll(AbstractSftpSubsystemHelper.DEFAULT_ACL_SUPPORTED_MASK),
                "Missing capabilities - expected=" + AbstractSftpSubsystemHelper.DEFAULT_ACL_SUPPORTED_MASK + ", actual="
                                                                                               + actual);
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}")
    public void sftpVersionSelector(int handleSize) throws Exception {
        initSftpTest(handleSize);
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
            assertEquals(selected.get(), sftp.getVersion(), "Mismatched negotiated version");
            testClient(client, sftp);
        }
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}") // see SSHD-621
    public void serverDoesNotSupportSftp(int handleSize) throws Exception {
        initSftpTest(handleSize);
        List<? extends SubsystemFactory> factories = sshd.getSubsystemFactories();
        assertEquals(1, GenericUtils.size(factories), "Mismatched subsystem factories count");

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
            assertNotNull(attrs, "No handle attributes");
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

            assertTrue(dotFiltered, "Dot entry not listed");
            assertTrue(dotdotFiltered, "Dot-dot entry not listed");
            assertEquals(1, dirEntries.size(), "Mismatched number of listed entries");
            assertNull(sftp.readDir(h), "Unexpected extra entry read after listing ended");
        }

        sftp.remove(file);

        byte[] smallBuf = "Hello world".getBytes(StandardCharsets.UTF_8);
        try (OutputStream os = sftp.write(file)) {
            os.write(smallBuf);
        }
        try (InputStream is = sftp.read(file)) {
            int readLen = is.read(smallBuf);
            assertEquals(smallBuf.length, readLen, "Mismatched read data length");
            assertEquals("Hello world", new String(smallBuf, StandardCharsets.UTF_8));

            int i = is.read();
            assertEquals(-1, i, "Unexpected read past EOF");
        }

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
            assertEquals(workBuf.length, readLen, "Mismatched read data length");

            int i = is.read();
            assertEquals(-1, i, "Unexpected read past EOF");
        }

        SftpClient.Attributes attributes = sftp.stat(file);
        assertTrue(attributes.isRegularFile(), "Test file not detected as regular");

        attributes = sftp.stat(dir);
        assertTrue(attributes.isDirectory(), "Test directory not reported as such");

        int nb = 0;
        boolean dotFiltered = false;
        boolean dotdotFiltered = false;
        for (SftpClient.DirEntry entry : sftp.readDir(dir)) {
            assertNotNull(entry, "Unexpected null entry");
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
        assertTrue(dotFiltered, "Dot entry not read");
        assertTrue(dotdotFiltered, "Dot-dot entry not read");
        assertEquals(1, nb, "Mismatched read dir entries");
        sftp.remove(file);
        sftp.rmdir(dir);
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}")
    public void createSymbolicLink(int handleSize) throws Exception {
        initSftpTest(handleSize);
        // Do not execute on windows as the file system does not support symlinks
        Assumptions.assumeTrue(OsUtils.isUNIX() || OsUtils.isOSX(), "Skip non-Unix O/S");
        List<? extends SubsystemFactory> factories = sshd.getSubsystemFactories();
        assertEquals(1, GenericUtils.size(factories), "Mismatched subsystem factories count");

        SubsystemFactory f = factories.get(0);
        assertObjectInstanceOf("Not an SFTP subsystem factory", SftpSubsystemFactory.class, f);

        SftpSubsystemFactory factory = (SftpSubsystemFactory) f;
        AtomicReference<LinkData> linkDataHolder = new AtomicReference<>();
        SftpEventListener listener = new AbstractSftpEventListenerAdapter() {
            @Override
            public void linking(ServerSession session, Path src, Path target, boolean symLink) {
                assertNull(linkDataHolder.getAndSet(new LinkData(src, target, symLink)), "Multiple linking calls");
            }

            @Override
            public void linked(
                    ServerSession session, Path src, Path target, boolean symLink, Throwable thrown) {
                LinkData data = linkDataHolder.get();
                assertNotNull(data, "No previous linking call");
                assertSame(data.getSource(), src, "Mismatched source");
                assertSame(data.getTarget(), target, "Mismatched target");
                assertEquals("Mismatched link type", data.isSymLink(), symLink);
                assertNull(thrown, "Unexpected failure");
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
                assertTrue(Files.exists(sourcePath), "Source file not created: " + sourcePath);
                assertEquals(data, readFile(remSrcPath), "Mismatched stored data in " + remSrcPath);

                Path linkPath = lclSftp.resolve("link-" + sourcePath.getFileName());
                String remLinkPath = "/" + CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, linkPath);
                LinkOption[] options = IoUtils.getLinkOptions(false);
                if (Files.exists(linkPath, options)) {
                    Files.delete(linkPath);
                }
                assertFalse(Files.exists(linkPath, options), "Target link exists before linking: " + linkPath);

                outputDebugMessage("Symlink %s => %s", remLinkPath, remSrcPath);
                c.symlink(remSrcPath, remLinkPath);

                assertTrue(Files.exists(linkPath, options), "Symlink not created: " + linkPath);
                assertEquals(data, readFile(remLinkPath), "Mismatched link data in " + remLinkPath);

                String str1 = c.readlink(remLinkPath);
                String str2 = c.realpath(remSrcPath);
                assertEquals(str1, str2, "Mismatched link vs. real path");
            } finally {
                c.disconnect();
            }
        } finally {
            factory.removeSftpEventListener(listener);
        }

        assertNotNull(linkDataHolder.getAndSet(null), "No symlink signalled");
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}") // see SSHD-903
    public void forcedVersionNegotiation(int handleSize) throws Exception {
        initSftpTest(handleSize);
        SftpModuleProperties.SFTP_VERSION.set(sshd, SftpConstants.SFTP_V3);
        try (SftpClient sftp = createSingleSessionClient()) {
            assertEquals(SftpConstants.SFTP_V3, sftp.getVersion(), "Mismatched negotiated version");
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

    @MethodSource("getParameters")
    @ParameterizedTest(name = "FILE_HANDLE_SIZE {0}")   // see SSHD-1022
    public void flushOutputStreamWithoutWrite(int handleSize) throws Exception {
        initSftpTest(handleSize);
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
