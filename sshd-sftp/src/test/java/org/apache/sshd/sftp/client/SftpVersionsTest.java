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

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils.NavigableMapBuilder;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.subsystem.SubsystemFactory;
import org.apache.sshd.sftp.SftpModuleProperties;
import org.apache.sshd.sftp.client.SftpClient.Attributes;
import org.apache.sshd.sftp.client.SftpClient.CloseableHandle;
import org.apache.sshd.sftp.client.SftpClient.DirEntry;
import org.apache.sshd.sftp.client.SftpClient.OpenMode;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpHelper;
import org.apache.sshd.sftp.server.AbstractSftpEventListenerAdapter;
import org.apache.sshd.sftp.server.DefaultGroupPrincipal;
import org.apache.sshd.sftp.server.SftpEventListener;
import org.apache.sshd.sftp.server.SftpSubsystem;
import org.apache.sshd.sftp.server.SftpSubsystemEnvironment;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
public class SftpVersionsTest extends AbstractSftpClientTestSupport {
    private static final List<Integer> VERSIONS = Collections.unmodifiableList(
            IntStream.rangeClosed(SftpSubsystemEnvironment.LOWER_SFTP_IMPL, SftpSubsystemEnvironment.HIGHER_SFTP_IMPL)
                    .boxed()
                    .collect(Collectors.toList()));

    private final int testVersion;

    public SftpVersionsTest(int version) throws IOException {
        testVersion = version;
    }

    @Parameters(name = "version={0}")
    public static Collection<Object[]> parameters() {
        return parameterize(VERSIONS);
    }

    @Before
    public void setUp() throws Exception {
        setupServer();

        Map<String, Object> props = sshd.getProperties();
        Object forced = props.remove(SftpModuleProperties.SFTP_VERSION.getName());
        if (forced != null) {
            outputDebugMessage("Removed forced version=%s", forced);
        }
    }

    public final int getTestedVersion() {
        return testVersion;
    }

    @Test // See SSHD-749
    public void testSftpOpenFlags() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp
                = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName());
        Path lclParent = assertHierarchyTargetFolderExists(lclSftp);
        Path lclFile = lclParent.resolve(getCurrentTestName() + "-" + getTestedVersion() + ".txt");
        Files.deleteIfExists(lclFile);

        Path parentPath = targetPath.getParent();
        String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, lclFile);
        try (ClientSession session = createAuthenticatedClientSession();
             SftpClient sftp = createSftpClient(session, getTestedVersion())) {
            try (OutputStream out = sftp.write(remotePath, OpenMode.Create, OpenMode.Write)) {
                out.write(getCurrentTestName().getBytes(StandardCharsets.UTF_8));
            }
            assertTrue("File should exist on disk: " + lclFile, Files.exists(lclFile));
            sftp.remove(remotePath);
        }
    }

    @Test
    public void testSftpVersionSelector() throws Exception {
        try (ClientSession session = createAuthenticatedClientSession();
             SftpClient sftp = createSftpClient(session, getTestedVersion())) {
            assertEquals("Mismatched negotiated version", getTestedVersion(), sftp.getVersion());
        }
    }

    @Test // see SSHD-572
    public void testSftpFileTimesUpdate() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp
                = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName());
        Path lclFile
                = assertHierarchyTargetFolderExists(lclSftp).resolve(getCurrentTestName() + "-" + getTestedVersion() + ".txt");
        Files.write(lclFile, getClass().getName().getBytes(StandardCharsets.UTF_8));
        Path parentPath = targetPath.getParent();
        String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, lclFile);
        try (ClientSession session = createAuthenticatedClientSession();
             SftpClient sftp = createSftpClient(session, getTestedVersion())) {
            Attributes attrs = sftp.lstat(remotePath);
            long expectedSeconds = TimeUnit.SECONDS.convert(System.currentTimeMillis() - TimeUnit.HOURS.toMillis(1L),
                    TimeUnit.MILLISECONDS);
            attrs.getFlags().clear();
            attrs.modifyTime(expectedSeconds);
            sftp.setStat(remotePath, attrs);

            attrs = sftp.lstat(remotePath);
            long actualSeconds = attrs.getModifyTime().to(TimeUnit.SECONDS);
            // The NTFS file system delays updates to the last access time for a file by up to 1 hour after the last
            // access
            if (expectedSeconds != actualSeconds) {
                System.err.append("Mismatched last modified time for ").append(lclFile.toString())
                        .append(" - expected=").append(String.valueOf(expectedSeconds))
                        .append('[').append(new Date(TimeUnit.SECONDS.toMillis(expectedSeconds)).toString()).append(']')
                        .append(", actual=").append(String.valueOf(actualSeconds))
                        .append('[').append(new Date(TimeUnit.SECONDS.toMillis(actualSeconds)).toString()).append(']')
                        .println();
            }
        }
    }

    @Test // see SSHD-573
    public void testSftpFileTypeAndPermissionsUpdate() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp
                = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName());
        Path subFolder = Files.createDirectories(lclSftp.resolve("sub-folder"));
        String subFolderName = subFolder.getFileName().toString();
        Path lclFile
                = assertHierarchyTargetFolderExists(lclSftp).resolve(getCurrentTestName() + "-" + getTestedVersion() + ".txt");
        String lclFileName = lclFile.getFileName().toString();
        Files.write(lclFile, getClass().getName().getBytes(StandardCharsets.UTF_8));

        Path parentPath = targetPath.getParent();
        String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, lclSftp);
        try (ClientSession session = createAuthenticatedClientSession();
             SftpClient sftp = createSftpClient(session, getTestedVersion())) {
            for (DirEntry entry : sftp.readDir(remotePath)) {
                String fileName = entry.getFilename();
                if (".".equals(fileName) || "..".equals(fileName)) {
                    continue;
                }

                Attributes attrs = validateSftpFileTypeAndPermissions(fileName, getTestedVersion(), entry.getAttributes());
                if (subFolderName.equals(fileName)) {
                    assertEquals("Mismatched sub-folder type", SftpConstants.SSH_FILEXFER_TYPE_DIRECTORY, attrs.getType());
                    assertTrue("Sub-folder not marked as directory", attrs.isDirectory());
                } else if (lclFileName.equals(fileName)) {
                    assertEquals("Mismatched sub-file type", SftpConstants.SSH_FILEXFER_TYPE_REGULAR, attrs.getType());
                    assertTrue("Sub-folder not marked as directory", attrs.isRegularFile());
                }
            }
        }
    }

    @Test // see SSHD-574
    public void testSftpACLEncodeDecode() throws Exception {
        AclEntryType[] types = AclEntryType.values();
        final List<AclEntry> aclExpected = new ArrayList<>(types.length);
        for (AclEntryType t : types) {
            aclExpected.add(AclEntry.newBuilder()
                    .setType(t)
                    .setFlags(EnumSet.allOf(AclEntryFlag.class))
                    .setPermissions(EnumSet.allOf(AclEntryPermission.class))
                    .setPrincipal(new DefaultGroupPrincipal(getCurrentTestName() + "@" + getClass().getPackage().getName()))
                    .build());
        }

        AtomicInteger numInvocations = new AtomicInteger(0);
        SftpSubsystemFactory factory = new SftpSubsystemFactory() {
            @Override
            public Command createSubsystem(ChannelSession channel) throws IOException {
                SftpSubsystem subsystem = new SftpSubsystem(
                        resolveExecutorService(),
                        getUnsupportedAttributePolicy(), getFileSystemAccessor(), getErrorStatusDataHandler()) {
                    @Override
                    protected NavigableMap<String, Object> resolveFileAttributes(Path file, int flags, LinkOption... options)
                            throws IOException {
                        NavigableMap<String, Object> attrs = super.resolveFileAttributes(file, flags, options);
                        if (GenericUtils.isEmpty(attrs)) {
                            attrs = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                        }

                        @SuppressWarnings("unchecked")
                        List<AclEntry> aclActual = (List<AclEntry>) attrs.put("acl", aclExpected);
                        if (aclActual != null) {
                            log.info("resolveFileAttributes(" + file + ") replaced ACL: " + aclActual);
                        }
                        return attrs;
                    }

                    @Override
                    protected void setFileAccessControl(Path file, List<AclEntry> aclActual, LinkOption... options)
                            throws IOException {
                        if (aclActual != null) {
                            assertListEquals("Mismatched ACL set for file=" + file, aclExpected, aclActual);
                            numInvocations.incrementAndGet();
                        }
                    }
                };
                Collection<? extends SftpEventListener> listeners = getRegisteredListeners();
                if (GenericUtils.size(listeners) > 0) {
                    for (SftpEventListener l : listeners) {
                        subsystem.addSftpEventListener(l);
                    }
                }

                return subsystem;
            }
        };

        factory.addSftpEventListener(new AbstractSftpEventListenerAdapter() {
            @Override
            public void modifyingAttributes(ServerSession session, Path path, Map<String, ?> attrs) {
                @SuppressWarnings("unchecked")
                List<AclEntry> aclActual = GenericUtils.isEmpty(attrs) ? null : (List<AclEntry>) attrs.get("acl");
                if (getTestedVersion() > SftpConstants.SFTP_V3) {
                    assertListEquals("Mismatched modifying ACL for file=" + path, aclExpected, aclActual);
                } else {
                    assertNull("Unexpected modifying ACL for file=" + path, aclActual);
                }
            }

            @Override
            public void modifiedAttributes(
                    ServerSession session, Path path, Map<String, ?> attrs, Throwable thrown) {
                @SuppressWarnings("unchecked")
                List<AclEntry> aclActual = GenericUtils.isEmpty(attrs) ? null : (List<AclEntry>) attrs.get("acl");
                if (getTestedVersion() > SftpConstants.SFTP_V3) {
                    assertListEquals("Mismatched modified ACL for file=" + path, aclExpected, aclActual);
                } else {
                    assertNull("Unexpected modified ACL for file=" + path, aclActual);
                }
            }
        });

        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName());
        Files.createDirectories(lclSftp.resolve("sub-folder"));
        Path lclFile = assertHierarchyTargetFolderExists(lclSftp)
                .resolve(getCurrentTestName() + "-" + getTestedVersion() + ".txt");
        Files.write(lclFile, getClass().getName().getBytes(StandardCharsets.UTF_8));

        Path parentPath = targetPath.getParent();
        String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, lclSftp);
        int numInvoked = 0;

        List<SubsystemFactory> factories = sshd.getSubsystemFactories();
        sshd.setSubsystemFactories(Collections.singletonList(factory));
        try (ClientSession session = createAuthenticatedClientSession();
             SftpClient sftp = createSftpClient(session, getTestedVersion())) {
            for (DirEntry entry : sftp.readDir(remotePath)) {
                String fileName = entry.getFilename();
                if (".".equals(fileName) || "..".equals(fileName)) {
                    continue;
                }

                Attributes attrs = validateSftpFileTypeAndPermissions(fileName, getTestedVersion(), entry.getAttributes());
                List<AclEntry> aclActual = attrs.getAcl();
                if (getTestedVersion() == SftpConstants.SFTP_V3) {
                    assertNull("Unexpected ACL for entry=" + fileName, aclActual);
                } else {
                    assertListEquals("Mismatched ACL for entry=" + fileName, aclExpected, aclActual);
                }

                attrs.getFlags().clear();
                attrs.setAcl(aclExpected);
                sftp.setStat(remotePath + "/" + fileName, attrs);
                if (getTestedVersion() > SftpConstants.SFTP_V3) {
                    numInvoked++;
                }
            }
        } finally {
            sshd.setSubsystemFactories(factories);
        }

        assertEquals("Mismatched invocations count", numInvoked, numInvocations.get());
    }

    @Test // see SSHD-575
    public void testSftpExtensionsEncodeDecode() throws Exception {
        Class<?> anchor = getClass();
        Map<String, String> expExtensions = NavigableMapBuilder.<String, String> builder(String.CASE_INSENSITIVE_ORDER)
                .put("class", anchor.getSimpleName())
                .put("package", anchor.getPackage().getName())
                .put("method", getCurrentTestName())
                .build();

        final AtomicInteger numInvocations = new AtomicInteger(0);
        SftpSubsystemFactory factory = new SftpSubsystemFactory() {
            @Override
            public Command createSubsystem(ChannelSession channel) throws IOException {
                SftpSubsystem subsystem = new SftpSubsystem(
                        resolveExecutorService(),
                        getUnsupportedAttributePolicy(), getFileSystemAccessor(), getErrorStatusDataHandler()) {
                    @Override
                    protected NavigableMap<String, Object> resolveFileAttributes(Path file, int flags, LinkOption... options)
                            throws IOException {
                        NavigableMap<String, Object> attrs = super.resolveFileAttributes(file, flags, options);
                        if (GenericUtils.isEmpty(attrs)) {
                            attrs = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                        }

                        @SuppressWarnings("unchecked")
                        Map<String, String> actExtensions = (Map<String, String>) attrs.put("extended", expExtensions);
                        if (actExtensions != null) {
                            log.info("resolveFileAttributes(" + file + ") replaced extensions: " + actExtensions);
                        }
                        return attrs;
                    }

                    @Override
                    protected void setFileExtensions(Path file, Map<String, byte[]> extensions, LinkOption... options)
                            throws IOException {
                        assertExtensionsMapEquals("setFileExtensions(" + file + ")", expExtensions, extensions);
                        numInvocations.incrementAndGet();

                        int currentVersion = getTestedVersion();
                        try {
                            super.setFileExtensions(file, extensions, options);
                            assertFalse("Expected exception not generated for version=" + currentVersion,
                                    currentVersion >= SftpConstants.SFTP_V6);
                        } catch (UnsupportedOperationException e) {
                            assertTrue("Unexpected exception for version=" + currentVersion,
                                    currentVersion >= SftpConstants.SFTP_V6);
                        }
                    }
                };
                Collection<? extends SftpEventListener> listeners = getRegisteredListeners();
                if (GenericUtils.size(listeners) > 0) {
                    for (SftpEventListener l : listeners) {
                        subsystem.addSftpEventListener(l);
                    }
                }

                return subsystem;
            }
        };

        factory.addSftpEventListener(new AbstractSftpEventListenerAdapter() {
            @Override
            public void modifyingAttributes(ServerSession session, Path path, Map<String, ?> attrs) {
                @SuppressWarnings("unchecked")
                Map<String, byte[]> actExtensions
                        = GenericUtils.isEmpty(attrs) ? null : (Map<String, byte[]>) attrs.get("extended");
                assertExtensionsMapEquals("modifying(" + path + ")", expExtensions, actExtensions);
            }

            @Override
            public void modifiedAttributes(ServerSession session, Path path, Map<String, ?> attrs, Throwable thrown) {
                @SuppressWarnings("unchecked")
                Map<String, byte[]> actExtensions
                        = GenericUtils.isEmpty(attrs) ? null : (Map<String, byte[]>) attrs.get("extended");
                assertExtensionsMapEquals("modified(" + path + ")", expExtensions, actExtensions);
            }
        });

        Path targetPath = detectTargetFolder();
        Path lclSftp
                = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName());
        Files.createDirectories(lclSftp.resolve("sub-folder"));
        Path lclFile
                = assertHierarchyTargetFolderExists(lclSftp).resolve(getCurrentTestName() + "-" + getTestedVersion() + ".txt");
        Files.write(lclFile, getClass().getName().getBytes(StandardCharsets.UTF_8));

        Path parentPath = targetPath.getParent();
        String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, lclSftp);
        int numInvoked = 0;

        List<SubsystemFactory> factories = sshd.getSubsystemFactories();
        sshd.setSubsystemFactories(Collections.singletonList(factory));
        try (ClientSession session = createAuthenticatedClientSession();
             SftpClient sftp = createSftpClient(session, getTestedVersion())) {
            for (DirEntry entry : sftp.readDir(remotePath)) {
                String fileName = entry.getFilename();
                if (".".equals(fileName) || "..".equals(fileName)) {
                    continue;
                }

                Attributes attrs = validateSftpFileTypeAndPermissions(fileName, getTestedVersion(), entry.getAttributes());
                Map<String, byte[]> actExtensions = attrs.getExtensions();
                assertExtensionsMapEquals("dirEntry=" + fileName, expExtensions, actExtensions);
                attrs.getFlags().clear();
                attrs.setStringExtensions(expExtensions);
                sftp.setStat(remotePath + "/" + fileName, attrs);
                numInvoked++;
            }
        } finally {
            sshd.setSubsystemFactories(factories);
        }

        assertEquals("Mismatched invocations count", numInvoked, numInvocations.get());
    }

    @Test // see SSHD-623
    public void testEndOfListIndicator() throws Exception {
        try (ClientSession session = createAuthenticatedClientSession();
             SftpClient sftp = createSftpClient(session, getTestedVersion())) {
            AtomicReference<Boolean> eolIndicator = new AtomicReference<>();
            int version = sftp.getVersion();
            Path targetPath = detectTargetFolder();
            Path parentPath = targetPath.getParent();
            String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, targetPath);

            try (CloseableHandle handle = sftp.openDir(remotePath)) {
                List<DirEntry> entries = sftp.readDir(handle, eolIndicator);
                for (int index = 1; entries != null; entries = sftp.readDir(handle, eolIndicator), index++) {
                    Boolean value = eolIndicator.get();
                    if (version < SftpConstants.SFTP_V6) {
                        assertNull("Unexpected indicator value at iteration #" + index, value);
                    } else {
                        assertNotNull("No indicator returned at iteration #" + index, value);
                        if (value) {
                            break;
                        }
                    }
                    eolIndicator.set(null); // make sure starting fresh
                }

                Boolean value = eolIndicator.get();
                if (version < SftpConstants.SFTP_V6) {
                    assertNull("Unexpected end-of-list indication received at end of entries", value);
                    assertNull("Unexpected no last entries indication", entries);
                } else {
                    assertNotNull("No end-of-list indication received at end of entries", value);
                    assertNotNull("No last received entries", entries);
                    assertTrue("Bad end-of-list value", value);
                }
            }
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getTestedVersion() + "]";
    }

    public static void assertExtensionsMapEquals(String message, Map<String, String> expected, Map<String, byte[]> actual) {
        assertMapEquals(message, expected, SftpHelper.toStringExtensions(actual));
    }

    private static Attributes validateSftpFileTypeAndPermissions(String fileName, int version, Attributes attrs) {
        int actualPerms = attrs.getPermissions();
        if (version == SftpConstants.SFTP_V3) {
            int expected = SftpHelper.permissionsToFileType(actualPerms);
            assertEquals(fileName + ": Mismatched file type", expected, attrs.getType());
        } else {
            int expected = SftpHelper.fileTypeToPermission(attrs.getType());
            assertTrue(fileName + ": Missing permision=0x" + Integer.toHexString(expected) + " in 0x"
                       + Integer.toHexString(actualPerms),
                    (actualPerms & expected) == expected);
        }

        return attrs;
    }
}
