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
package org.apache.sshd.scp.client;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import ch.ethz.ssh2.Connection;
import ch.ethz.ssh2.ConnectionInfo;
import ch.ethz.ssh2.SCPClient;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.common.io.BuiltinIoServiceFactoryFactories;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.scp.common.ScpException;
import org.apache.sshd.scp.common.ScpFileOpener;
import org.apache.sshd.scp.common.ScpHelper;
import org.apache.sshd.scp.common.ScpTransferEventListener;
import org.apache.sshd.scp.common.helpers.DefaultScpFileOpener;
import org.apache.sshd.scp.common.helpers.ScpAckInfo;
import org.apache.sshd.scp.common.helpers.ScpDirEndCommandDetails;
import org.apache.sshd.scp.common.helpers.ScpIoUtils;
import org.apache.sshd.scp.common.helpers.ScpPathCommandDetailsSupport;
import org.apache.sshd.scp.common.helpers.ScpReceiveDirCommandDetails;
import org.apache.sshd.scp.common.helpers.ScpReceiveFileCommandDetails;
import org.apache.sshd.scp.server.ScpCommand;
import org.apache.sshd.scp.server.ScpCommandFactory;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.JSchLogger;
import org.apache.sshd.util.test.SimpleUserInfo;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * Test for SCP support.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ScpTest extends AbstractScpTestSupport {
    public ScpTest() throws IOException {
        super();
    }

    @BeforeClass
    public static void setupClientAndServer() throws Exception {
        JSchLogger.init();
        setupClientAndServer(ScpTest.class);
    }

    @Test
    public void testNormalizedScpRemotePaths() throws Exception {
        // see SSHD-822
        assumeNotIoServiceProvider(
                EnumSet.of(BuiltinIoServiceFactoryFactories.NETTY, BuiltinIoServiceFactoryFactories.MINA));
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(scpRoot);

        Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
        Path localFile = localDir.resolve("file.txt");
        byte[] data
                = CommonTestSupportUtils.writeFile(localFile, getClass().getName() + "#" + getCurrentTestName() + IoUtils.EOL);

        Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
        Path remoteFile = remoteDir.resolve(localFile.getFileName().toString());
        String localPath = localFile.toString();
        String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteFile);
        String[] remoteComps = GenericUtils.split(remotePath, '/');
        Factory<? extends Random> factory = client.getRandomFactory();
        Random rnd = factory.create();
        try (CloseableScpClient scp = createCloseableScpClient()) {
            StringBuilder sb = new StringBuilder(remotePath.length() + Long.SIZE);
            for (int i = 0; i < Math.max(Long.SIZE, remoteComps.length); i++) {
                if (sb.length() > 0) {
                    sb.setLength(0); // start again
                }

                sb.append(remoteComps[0]);
                for (int j = 1; j < remoteComps.length; j++) {
                    String name = remoteComps[j];
                    slashify(sb, rnd);
                    sb.append(name);
                }
                slashify(sb, rnd);

                String path = sb.toString();
                scp.upload(localPath, path);
                assertTrue("Remote file not ready for " + path,
                        waitForFile(remoteFile, data.length, TimeUnit.SECONDS.toMillis(5L)));

                byte[] actual = Files.readAllBytes(remoteFile);
                assertArrayEquals("Mismatched uploaded data for " + path, data, actual);
                Files.delete(remoteFile);
                assertFalse("Remote file (" + remoteFile + ") not deleted for " + path, Files.exists(remoteFile));
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
    public void testUploadAbsoluteDriveLetter() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(scpRoot);

        Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
        Path localFile = localDir.resolve("file-1.txt");
        byte[] data
                = CommonTestSupportUtils.writeFile(localFile, getClass().getName() + "#" + getCurrentTestName() + IoUtils.EOL);

        Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
        Path remoteFile = remoteDir.resolve(localFile.getFileName().toString());
        String localPath = localFile.toString();
        String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteFile);
        try (CloseableScpClient scp = createCloseableScpClient()) {
            scp.upload(localPath, remotePath);
            assertFileLength(remoteFile, data.length, DEFAULT_TIMEOUT);

            Path secondRemote = remoteDir.resolve("file-2.txt");
            String secondPath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, secondRemote);
            scp.upload(localPath, secondPath);
            assertFileLength(secondRemote, data.length, DEFAULT_TIMEOUT);

            Path pathRemote = remoteDir.resolve("file-path.txt");
            String pathPath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, pathRemote);
            scp.upload(localFile, pathPath);
            assertFileLength(pathRemote, data.length, DEFAULT_TIMEOUT);
        }
    }

    @Test
    public void testScpUploadOverwrite() throws Exception {
        String data = getClass().getName() + "#" + getCurrentTestName() + IoUtils.EOL;

        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(scpRoot);

        Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
        Path localFile = localDir.resolve("file.txt");
        CommonTestSupportUtils.writeFile(localFile, data);

        Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
        Path remoteFile = remoteDir.resolve(localFile.getFileName());
        CommonTestSupportUtils.writeFile(remoteFile, data + data);

        String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteFile);
        try (CloseableScpClient scp = createCloseableScpClient()) {
            scp.upload(localFile.toString(), remotePath);
        }

        assertFileLength(remoteFile, data.length(), DEFAULT_TIMEOUT);
    }

    @Test
    public void testScpUploadZeroLengthFile() throws Exception {
        Path targetPath = detectTargetFolder();
        Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
        Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
        Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
        Path zeroLocal = localDir.resolve("zero.txt");

        try (FileChannel fch = FileChannel.open(zeroLocal, StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            if (fch.size() > 0L) {
                fch.truncate(0L);
            }
        }
        assertEquals("Non-zero size for local file=" + zeroLocal, 0L, Files.size(zeroLocal));

        Path zeroRemote = remoteDir.resolve(zeroLocal.getFileName());
        if (Files.exists(zeroRemote)) {
            Files.delete(zeroRemote);
        }

        String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(targetPath.getParent(), zeroRemote);
        try (CloseableScpClient scp = createCloseableScpClient()) {
            scp.upload(zeroLocal.toString(), remotePath);
        }
        assertFileLength(zeroRemote, 0L, DEFAULT_TIMEOUT);
    }

    @Test
    public void testScpDownloadZeroLengthFile() throws Exception {
        Path targetPath = detectTargetFolder();
        Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
        Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
        Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
        Path zeroLocal = localDir.resolve(getCurrentTestName());
        if (Files.exists(zeroLocal)) {
            Files.delete(zeroLocal);
        }

        Path zeroRemote = remoteDir.resolve(zeroLocal.getFileName());
        try (FileChannel fch = FileChannel.open(zeroRemote, StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            if (fch.size() > 0L) {
                fch.truncate(0L);
            }
        }
        assertEquals("Non-zero size for remote file=" + zeroRemote, 0L, Files.size(zeroRemote));

        String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(targetPath.getParent(), zeroRemote);
        try (CloseableScpClient scp = createCloseableScpClient()) {
            scp.download(remotePath, zeroLocal.toString());
        }
        assertFileLength(zeroLocal, 0L, DEFAULT_TIMEOUT);
    }

    @Test
    public void testScpNativeOnSingleFile() throws Exception {
        // see SSHD-822
        assumeNotIoServiceProvider(EnumSet.of(BuiltinIoServiceFactoryFactories.NETTY));

        String data = getClass().getName() + "#" + getCurrentTestName() + IoUtils.EOL;

        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(scpRoot);

        Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
        Path localOutFile = localDir.resolve("file-1.txt");
        Path remoteDir = scpRoot.resolve("remote");
        Path remoteOutFile = remoteDir.resolve(localOutFile.getFileName());

        try (CloseableScpClient scp = createCloseableScpClient()) {
            CommonTestSupportUtils.writeFile(localOutFile, data);

            assertFalse("Remote folder already exists: " + remoteDir, Files.exists(remoteDir));

            String localOutPath = localOutFile.toString();
            String remoteOutPath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteOutFile);
            outputDebugMessage("Expect upload failure %s => %s", localOutPath, remoteOutPath);
            try {
                scp.upload(localOutPath, remoteOutPath);
                fail("Expected IOException for 1st time " + remoteOutPath);
            } catch (IOException e) {
                // ok
            }

            assertHierarchyTargetFolderExists(remoteDir);
            outputDebugMessage("Expect upload success %s => %s", localOutPath, remoteOutPath);
            scp.upload(localOutPath, remoteOutPath);
            assertFileLength(remoteOutFile, data.length(), DEFAULT_TIMEOUT);

            Path secondLocal = localDir.resolve(localOutFile.getFileName());
            String downloadTarget = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, secondLocal);
            outputDebugMessage("Expect download success %s => %s", remoteOutPath, downloadTarget);
            scp.download(remoteOutPath, downloadTarget);
            assertFileLength(secondLocal, data.length(), DEFAULT_TIMEOUT);

            Path localPath = localDir.resolve("file-path.txt");
            downloadTarget = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, localPath);
            outputDebugMessage("Expect download success %s => %s", remoteOutPath, downloadTarget);
            scp.download(remoteOutPath, downloadTarget);
            assertFileLength(localPath, data.length(), DEFAULT_TIMEOUT);
        }
    }

    @Test
    public void testScpNativeOnMultipleFiles() throws Exception {
        // see SSHD-822
        assumeNotIoServiceProvider(EnumSet.of(BuiltinIoServiceFactoryFactories.MINA, BuiltinIoServiceFactoryFactories.NETTY));

        try (CloseableScpClient scp = createCloseableScpClient()) {
            Path targetPath = detectTargetFolder();
            Path parentPath = targetPath.getParent();
            Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                    ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
            CommonTestSupportUtils.deleteRecursive(scpRoot);

            Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
            Path local1 = localDir.resolve("file-1.txt");
            byte[] data
                    = CommonTestSupportUtils.writeFile(local1, getClass().getName() + "#" + getCurrentTestName() + IoUtils.EOL);

            Path local2 = localDir.resolve("file-2.txt");
            Files.write(local2, data);

            Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
            Path remote1 = remoteDir.resolve(local1.getFileName());
            String remote1Path = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remote1);
            String[] locals = { local1.toString(), local2.toString() };
            try {
                scp.upload(locals, remote1Path);
                fail("Unexpected upload success to missing remote file: " + remote1Path);
            } catch (IOException e) {
                // Ok
            }

            Files.write(remote1, data);
            try {
                scp.upload(locals, remote1Path);
                fail("Unexpected upload success to existing remote file: " + remote1Path);
            } catch (IOException e) {
                // Ok
            }

            Path remoteSubDir = assertHierarchyTargetFolderExists(remoteDir.resolve("dir"));
            scp.upload(locals, CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteSubDir));

            Path remoteSub1 = remoteSubDir.resolve(local1.getFileName());
            assertFileLength(remoteSub1, data.length, DEFAULT_TIMEOUT);

            Path remoteSub2 = remoteSubDir.resolve(local2.getFileName());
            assertFileLength(remoteSub2, data.length, DEFAULT_TIMEOUT);

            String[] remotes = {
                    CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteSub1),
                    CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteSub2),
            };

            try {
                scp.download(remotes, CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, local1));
                fail("Unexpected download success to existing local file: " + local1);
            } catch (IOException e) {
                // Ok
            }

            Path localSubDir = localDir.resolve("dir");
            try {
                scp.download(remotes, localSubDir);
                fail("Unexpected download success to non-existing folder: " + localSubDir);
            } catch (IOException e) {
                // Ok
            }

            assertHierarchyTargetFolderExists(localSubDir);
            scp.download(remotes, localSubDir);

            assertFileLength(localSubDir.resolve(remoteSub1.getFileName()), data.length, DEFAULT_TIMEOUT);
            assertFileLength(localSubDir.resolve(remoteSub2.getFileName()), data.length, DEFAULT_TIMEOUT);
        }
    }

    @Test
    public void testScpNativeOnRecursiveDirs() throws Exception {
        try (CloseableScpClient scp = createCloseableScpClient()) {
            Path targetPath = detectTargetFolder();
            Path parentPath = targetPath.getParent();
            Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                    ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
            CommonTestSupportUtils.deleteRecursive(scpRoot);

            Path localDir = scpRoot.resolve("local");
            Path localSubDir = assertHierarchyTargetFolderExists(localDir.resolve("dir"));
            Path localSub1 = localSubDir.resolve("file-1.txt");
            byte[] data = CommonTestSupportUtils.writeFile(localSub1,
                    getClass().getName() + "#" + getCurrentTestName() + IoUtils.EOL);
            Path localSub2 = localSubDir.resolve("file-2.txt");
            Files.write(localSub2, data);

            Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
            scp.upload(localSubDir, CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteDir),
                    ScpClient.Option.Recursive);

            Path remoteSubDir = remoteDir.resolve(localSubDir.getFileName());
            assertFileLength(remoteSubDir.resolve(localSub1.getFileName()), data.length, DEFAULT_TIMEOUT);
            assertFileLength(remoteSubDir.resolve(localSub2.getFileName()), data.length, DEFAULT_TIMEOUT);

            CommonTestSupportUtils.deleteRecursive(localSubDir);

            scp.download(CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteSubDir), localDir,
                    ScpClient.Option.Recursive);
            assertFileLength(localSub1, data.length, DEFAULT_TIMEOUT);
            assertFileLength(localSub2, data.length, DEFAULT_TIMEOUT);
        }
    }

    @Test // see SSHD-893
    public void testScpNativeOnDirWithPattern() throws Exception {
        try (CloseableScpClient scp = createCloseableScpClient()) {
            Path targetPath = detectTargetFolder();
            Path parentPath = targetPath.getParent();
            Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                    ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
            CommonTestSupportUtils.deleteRecursive(scpRoot);

            Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
            Path local1 = localDir.resolve("file-1.txt");
            byte[] data
                    = CommonTestSupportUtils.writeFile(local1, getClass().getName() + "#" + getCurrentTestName() + IoUtils.EOL);
            Path local2 = localDir.resolve("file-2.txt");
            Files.write(local2, data);

            Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
            String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteDir);
            scp.upload(localDir.toString() + File.separator + "*", remotePath);
            assertFileLength(remoteDir.resolve(local1.getFileName()), data.length, DEFAULT_TIMEOUT);
            assertFileLength(remoteDir.resolve(local2.getFileName()), data.length, DEFAULT_TIMEOUT);

            Files.delete(local1);
            Files.delete(local2);
            scp.download(remotePath + "/*", localDir);
            assertFileLength(local1, data.length, DEFAULT_TIMEOUT);
            assertFileLength(local2, data.length, DEFAULT_TIMEOUT);
        }
    }

    @Test
    public void testScpVirtualOnDirWithPattern() throws Exception {
        Path remoteDir = getTempTargetRelativeFile(
                getClass().getSimpleName(), getCurrentTestName(), ScpHelper.SCP_COMMAND_PREFIX, "virtual");
        CommonTestSupportUtils.deleteRecursive(remoteDir); // start fresh
        Files.createDirectories(remoteDir);
        sshd.setFileSystemFactory(new VirtualFileSystemFactory(remoteDir));

        try (CloseableScpClient scp = createCloseableScpClient()) {
            Path targetPath = detectTargetFolder();
            Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                    ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
            CommonTestSupportUtils.deleteRecursive(scpRoot);

            Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
            Path local1 = localDir.resolve("file-1.txt");
            byte[] data
                    = CommonTestSupportUtils.writeFile(local1, getClass().getName() + "#" + getCurrentTestName() + IoUtils.EOL);
            Path local2 = localDir.resolve("file-2.txt");
            Files.write(local2, data);

            scp.upload(localDir.toString() + File.separator + "*", "/");

            Path remote1 = remoteDir.resolve(local1.getFileName());
            Path remote2 = remoteDir.resolve(local2.getFileName());

            assertFileLength(remote1, data.length, DEFAULT_TIMEOUT);
            assertFileLength(remote2, data.length, DEFAULT_TIMEOUT);

            Files.delete(local1);
            Files.delete(local2);

            scp.download("/*", localDir);
            assertFileLength(local1, data.length, DEFAULT_TIMEOUT);
            assertFileLength(local2, data.length, DEFAULT_TIMEOUT);

            Files.delete(remote1);
            Files.delete(remote2);

            CommonTestSupportUtils.deleteRecursive(remoteDir);
        }
    }

    @Test
    public void testScpNativeOnMixedDirAndFiles() throws Exception {
        try (CloseableScpClient scp = createCloseableScpClient()) {
            Path targetPath = detectTargetFolder();
            Path parentPath = targetPath.getParent();
            Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                    ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
            CommonTestSupportUtils.deleteRecursive(scpRoot);

            Path localDir = scpRoot.resolve("local");
            Path localSubDir = assertHierarchyTargetFolderExists(localDir.resolve("dir"));
            Path local1 = localDir.resolve("file-1.txt");
            byte[] data
                    = CommonTestSupportUtils.writeFile(local1, getClass().getName() + "#" + getCurrentTestName() + IoUtils.EOL);
            Path localSub2 = localSubDir.resolve("file-2.txt");
            Files.write(localSub2, data);

            Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
            String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteDir);
            scp.upload(localDir.toString() + File.separator + "*", remotePath, ScpClient.Option.Recursive);
            assertFileLength(remoteDir.resolve(local1.getFileName()), data.length, DEFAULT_TIMEOUT);

            Path remoteSubDir = remoteDir.resolve(localSubDir.getFileName());
            assertFileLength(remoteSubDir.resolve(localSub2.getFileName()), data.length, DEFAULT_TIMEOUT);

            Files.delete(local1);
            CommonTestSupportUtils.deleteRecursive(localSubDir);

            scp.download(remotePath + "/*", localDir);
            assertFileLength(local1, data.length, DEFAULT_TIMEOUT);
            assertFalse("Unexpected recursive local file: " + localSub2, Files.exists(localSub2));

            Files.delete(local1);
            scp.download(remotePath + "/*", localDir, ScpClient.Option.Recursive);
            assertFileLength(local1, data.length, DEFAULT_TIMEOUT);
            assertFileLength(localSub2, data.length, DEFAULT_TIMEOUT);
        }
    }

    @Test
    public void testScpNativePreserveAttributes() throws Exception {
        try (CloseableScpClient scp = createCloseableScpClient()) {
            Path targetPath = detectTargetFolder();
            Path parentPath = targetPath.getParent();
            Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                    ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
            CommonTestSupportUtils.deleteRecursive(scpRoot);

            Path localDir = scpRoot.resolve("local");
            Path localSubDir = assertHierarchyTargetFolderExists(localDir.resolve("dir"));
            // convert everything to seconds since this is the SCP timestamps granularity
            final long lastModMillis = System.currentTimeMillis() - TimeUnit.DAYS.toMillis(1);
            final long lastModSecs = TimeUnit.MILLISECONDS.toSeconds(lastModMillis);
            Path local1 = localDir.resolve("file-1.txt");
            byte[] data
                    = CommonTestSupportUtils.writeFile(local1, getClass().getName() + "#" + getCurrentTestName() + IoUtils.EOL);

            File lclFile1 = local1.toFile();
            boolean lcl1ModSet = lclFile1.setLastModified(lastModMillis);
            lclFile1.setExecutable(true, true);
            lclFile1.setWritable(false, false);

            Path localSub2 = localSubDir.resolve("file-2.txt");
            Files.write(localSub2, data);
            File lclSubFile2 = localSub2.toFile();
            boolean lclSub2ModSet = lclSubFile2.setLastModified(lastModMillis);

            Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
            String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteDir);
            scp.upload(localDir.toString() + File.separator + "*", remotePath, ScpClient.Option.Recursive,
                    ScpClient.Option.PreserveAttributes);

            Path remote1 = remoteDir.resolve(local1.getFileName());
            assertFileLength(remote1, data.length, DEFAULT_TIMEOUT);

            File remFile1 = remote1.toFile();
            assertLastModifiedTimeEquals(remFile1, lcl1ModSet, lastModSecs);

            Path remoteSubDir = remoteDir.resolve(localSubDir.getFileName());
            Path remoteSub2 = remoteSubDir.resolve(localSub2.getFileName());
            assertFileLength(remoteSub2, data.length, DEFAULT_TIMEOUT);

            File remSubFile2 = remoteSub2.toFile();
            assertLastModifiedTimeEquals(remSubFile2, lclSub2ModSet, lastModSecs);

            CommonTestSupportUtils.deleteRecursive(localDir);
            assertHierarchyTargetFolderExists(localDir);

            scp.download(remotePath + "/*", localDir, ScpClient.Option.Recursive, ScpClient.Option.PreserveAttributes);
            assertFileLength(local1, data.length, DEFAULT_TIMEOUT);
            assertLastModifiedTimeEquals(lclFile1, lcl1ModSet, lastModSecs);
            assertFileLength(localSub2, data.length, DEFAULT_TIMEOUT);
            assertLastModifiedTimeEquals(lclSubFile2, lclSub2ModSet, lastModSecs);
        }
    }

    @Test
    public void testStreamsUploadAndDownload() throws Exception {
        try (CloseableScpClient scp = createCloseableScpClient()) {
            Path targetPath = detectTargetFolder();
            Path parentPath = targetPath.getParent();
            Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                    ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
            CommonTestSupportUtils.deleteRecursive(scpRoot);

            Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
            Path remoteFile = remoteDir.resolve("file.txt");
            String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteFile);
            byte[] data = (getClass().getName() + "#" + getCurrentTestName()).getBytes(StandardCharsets.UTF_8);
            outputDebugMessage("Upload data to %s", remotePath);
            scp.upload(data, remotePath, EnumSet.allOf(PosixFilePermission.class), null);
            assertFileLength(remoteFile, data.length, DEFAULT_TIMEOUT);

            byte[] uploaded = Files.readAllBytes(remoteFile);
            assertArrayEquals("Mismatched uploaded data", data, uploaded);

            outputDebugMessage("Download data from %s", remotePath);
            byte[] downloaded = scp.downloadBytes(remotePath);
            assertArrayEquals("Mismatched downloaded data", uploaded, downloaded);
        }
    }

    @Test // see SSHD-649
    public void testScpFileOpener() throws Exception {
        class TrackingFileOpener extends DefaultScpFileOpener {
            private final AtomicInteger readCount = new AtomicInteger(0);
            private final AtomicInteger writeCount = new AtomicInteger(0);

            TrackingFileOpener() {
                super();
            }

            public AtomicInteger getReadCount() {
                return readCount;
            }

            public AtomicInteger getWriteCount() {
                return writeCount;
            }

            @Override
            public InputStream openRead(
                    Session session, Path file, long size, Set<PosixFilePermission> permissions, OpenOption... options)
                    throws IOException {
                int count = readCount.incrementAndGet();
                outputDebugMessage("openRead(%s)[size=%d][%s] permissions=%s: count=%d",
                        session, size, file, permissions, count);
                return super.openRead(session, file, size, permissions, options);
            }

            @Override
            public OutputStream openWrite(
                    Session session, Path file, long size, Set<PosixFilePermission> permissions, OpenOption... options)
                    throws IOException {
                int count = writeCount.incrementAndGet();
                outputDebugMessage("openWrite(%s)[size=%d][%s] permissions=%s: count=%d",
                        session, size, file, permissions, count);
                return super.openWrite(session, file, size, permissions, options);
            }
        }

        ScpCommandFactory factory = (ScpCommandFactory) sshd.getCommandFactory();
        ScpFileOpener opener = factory.getScpFileOpener();
        TrackingFileOpener serverOpener = new TrackingFileOpener();
        factory.setScpFileOpener(serverOpener);
        try (ClientSession session = createAuthenticatedClientSession()) {
            TrackingFileOpener clientOpener = new TrackingFileOpener();
            ScpClientCreator creator = ScpClientCreator.instance();
            ScpClient scp = creator.createScpClient(session, clientOpener);

            Path targetPath = detectTargetFolder();
            Path parentPath = targetPath.getParent();
            Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                    ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
            CommonTestSupportUtils.deleteRecursive(scpRoot);

            Path remoteDir = assertHierarchyTargetFolderExists(scpRoot);
            Path localFile = remoteDir.resolve("data.txt");
            byte[] data = (getClass().getName() + "#" + getCurrentTestName()).getBytes(StandardCharsets.UTF_8);
            Files.write(localFile, data);

            Path remoteFile = remoteDir.resolve("upload.txt");
            String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteFile);
            outputDebugMessage("Upload data to %s", remotePath);
            scp.upload(localFile, remotePath);
            assertFileLength(remoteFile, data.length, DEFAULT_TIMEOUT);

            AtomicInteger serverRead = serverOpener.getReadCount();
            assertEquals("Mismatched server upload open read count", 0, serverRead.get());

            AtomicInteger serverWrite = serverOpener.getWriteCount();
            assertEquals("Mismatched server upload write count", 1, serverWrite.getAndSet(0));

            AtomicInteger clientRead = clientOpener.getReadCount();
            assertEquals("Mismatched client upload read count", 1, clientRead.getAndSet(0));

            AtomicInteger clientWrite = clientOpener.getWriteCount();
            assertEquals("Mismatched client upload write count", 0, clientWrite.get());

            Files.delete(localFile);
            scp.download(remotePath, localFile);
            assertFileLength(localFile, data.length, DEFAULT_TIMEOUT);

            assertEquals("Mismatched server download open read count", 1, serverRead.getAndSet(0));
            assertEquals("Mismatched server download write count", 0, serverWrite.get());
            assertEquals("Mismatched client download read count", 0, clientRead.get());
            assertEquals("Mismatched client download write count", 1, clientWrite.getAndSet(0));
        } finally {
            factory.setScpFileOpener(opener);
        }
    }

    @Test // see SSHD-628
    public void testScpExitStatusPropagation() throws Exception {
        final int testExitValue = 7365;
        class InternalScpCommand extends ScpCommand {

            InternalScpCommand(String command, CloseableExecutorService executorService,
                               int sendSize, int receiveSize, ScpFileOpener opener, ScpTransferEventListener eventListener) {
                super(command, executorService, sendSize, receiveSize, opener, eventListener);
            }

            @Override
            protected void writeCommandResponseMessage(String command, int exitValue, String exitMessage) throws IOException {
                outputDebugMessage("writeCommandResponseMessage(%s) status=%d", command, exitValue);
                super.writeCommandResponseMessage(command, testExitValue, exitMessage);
            }

            @Override
            protected void onExit(int exitValue, String exitMessage) {
                outputDebugMessage("onExit(%s) status=%d", this, exitValue);
                super.onExit((exitValue == ScpAckInfo.OK) ? testExitValue : exitValue, exitMessage);
            }
        }

        ScpCommandFactory factory = (ScpCommandFactory) sshd.getCommandFactory();
        sshd.setCommandFactory(new ScpCommandFactory() {
            @Override
            public Command createCommand(ChannelSession channel, String command) {
                ValidateUtils.checkTrue(
                        command.startsWith(ScpHelper.SCP_COMMAND_PREFIX), "Bad SCP command: %s", command);
                return new InternalScpCommand(
                        command,
                        resolveExecutorService(command),
                        getSendBufferSize(), getReceiveBufferSize(),
                        DefaultScpFileOpener.INSTANCE,
                        ScpTransferEventListener.EMPTY);
            }
        });

        try (CloseableScpClient scp = createCloseableScpClient()) {
            Path targetPath = detectTargetFolder();
            Path parentPath = targetPath.getParent();
            Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                    ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
            CommonTestSupportUtils.deleteRecursive(scpRoot);

            Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
            Path remoteFile = remoteDir.resolve("file.txt");
            String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteFile);
            byte[] data = (getClass().getName() + "#" + getCurrentTestName()).getBytes(StandardCharsets.UTF_8);
            outputDebugMessage("Upload data to %s", remotePath);
            try {
                scp.upload(data, remotePath, EnumSet.allOf(PosixFilePermission.class), null);
                outputDebugMessage("Upload success to %s", remotePath);
            } catch (ScpException e) {
                Integer exitCode = e.getExitStatus();
                assertNotNull("No upload exit status", exitCode);
                assertEquals("Mismatched upload exit status", testExitValue, exitCode.intValue());
            }

            if (Files.deleteIfExists(remoteFile)) {
                outputDebugMessage("Deleted remote file %s", remoteFile);
            }

            try (OutputStream out = Files.newOutputStream(remoteFile)) {
                out.write(data);
            }

            try {
                byte[] downloaded = scp.downloadBytes(remotePath);
                outputDebugMessage("Download success to %s: %s", remotePath, new String(downloaded, StandardCharsets.UTF_8));
            } catch (ScpException e) {
                Integer exitCode = e.getExitStatus();
                assertNotNull("No download exit status", exitCode);
                assertEquals("Mismatched download exit status", testExitValue, exitCode.intValue());
            }
        } finally {
            sshd.setCommandFactory(factory);
        }
    }

    // see
    // http://stackoverflow.com/questions/2717936/file-createnewfile-creates-files-with-last-modified-time-before-actual-creatio
    // See https://msdn.microsoft.com/en-us/library/ms724290(VS.85).aspx
    private static void assertLastModifiedTimeEquals(File file, boolean modSuccess, long expectedSeconds) {
        long expectedMillis = TimeUnit.SECONDS.toMillis(expectedSeconds);
        long actualMillis = file.lastModified();
        long actualSeconds = TimeUnit.MILLISECONDS.toSeconds(actualMillis);
        // if failed to set the local file time, don't expect it to be the same
        if (!modSuccess) {
            System.err.append("Failed to set last modified time of ").append(file.getAbsolutePath())
                    .append(" to ").append(String.valueOf(expectedMillis))
                    .append(" - ").println(new Date(expectedMillis));
            System.err.append("\t\t").append("Current value: ").append(String.valueOf(actualMillis))
                    .append(" - ").println(new Date(actualMillis));
            return;
        }

        if (OsUtils.isWin32()) {
            // The NTFS file system delays updates to the last access time for a file by up to 1 hour after the last
            // access
            if (expectedSeconds != actualSeconds) {
                System.err.append("Mismatched last modified time for ").append(file.getAbsolutePath())
                        .append(" - expected=").append(String.valueOf(expectedSeconds))
                        .append('[').append(new Date(expectedMillis).toString()).append(']')
                        .append(", actual=").append(String.valueOf(actualSeconds))
                        .append('[').append(new Date(actualMillis).toString()).append(']')
                        .println();
            }
        } else {
            assertEquals("Mismatched last modified time for " + file.getAbsolutePath(), expectedSeconds, actualSeconds);
        }
    }

    @Test
    public void testJschScp() throws Exception {
        com.jcraft.jsch.Session session = getJschSession();
        try {
            String data = getCurrentTestName() + "\n";

            String unixDir = "target/scp";
            String fileName = getCurrentTestName() + ".txt";
            String unixPath = unixDir + "/" + fileName;
            Path root = Paths.get(unixDir);
            Path target = Paths.get(unixPath);
            CommonTestSupportUtils.deleteRecursive(root);
            Files.createDirectories(root);
            assertTrue("Failed to ensure existence of " + root, Files.exists(root));

            Files.deleteIfExists(target);
            assertFalse("Failed to delete 1st time: " + target, Files.exists(target));
            sendFile(session, unixPath, target, data);
            assertFileLength(target, data.length(), DEFAULT_TIMEOUT);

            Files.deleteIfExists(target);
            assertFalse("Failed to delete 2nd time: " + target, Files.exists(target));
            sendFile(session, unixDir, target, data);
            assertFileLength(target, data.length(), DEFAULT_TIMEOUT);

            sendFileError(session, "target", ScpHelper.SCP_COMMAND_PREFIX, data);

            readFileError(session, unixDir);

            assertEquals("Mismatched file data", data, readFile(session, unixPath, target));
            assertEquals("Mismatched dir data", data, readDir(session, unixDir, target));

            Files.deleteIfExists(target);
            Files.deleteIfExists(root);

            sendDir(session, "target", ScpHelper.SCP_COMMAND_PREFIX, fileName, data);
            assertFileLength(target, data.length(), DEFAULT_TIMEOUT);
        } finally {
            session.disconnect();
        }
    }

    protected com.jcraft.jsch.Session getJschSession() throws JSchException {
        JSch sch = new JSch();
        com.jcraft.jsch.Session session = sch.getSession(getCurrentTestName(), TEST_LOCALHOST, port);
        session.setUserInfo(new SimpleUserInfo(getCurrentTestName()));
        session.connect();
        return session;
    }

    @Test
    public void testWithGanymede() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(scpRoot);

        byte[] expected = (getClass().getName() + "#" + getCurrentTestName()).getBytes(StandardCharsets.UTF_8);
        Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
        String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, remoteDir);
        String fileName = "file.txt";
        Path remoteFile = remoteDir.resolve(fileName);
        String mode = ScpPathCommandDetailsSupport.getOctalPermissions(EnumSet.of(
                PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE,
                PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE,
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));

        ch.ethz.ssh2.log.Logger.enabled = true;
        Connection conn = new Connection(TEST_LOCALHOST, port);
        try {
            ConnectionInfo info = conn.connect(null,
                    (int) TimeUnit.SECONDS.toMillis(5L), (int) TimeUnit.SECONDS.toMillis(13L));
            outputDebugMessage("Connected: kex=%s, key-type=%s, c2senc=%s, s2cenc=%s, c2mac=%s, s2cmac=%s",
                    info.keyExchangeAlgorithm, info.serverHostKeyAlgorithm,
                    info.clientToServerCryptoAlgorithm, info.serverToClientCryptoAlgorithm,
                    info.clientToServerMACAlgorithm, info.serverToClientMACAlgorithm);
            assertTrue("Failed to authenticate", conn.authenticateWithPassword(getCurrentTestName(), getCurrentTestName()));

            SCPClient scpClient = new SCPClient(conn);
            try (OutputStream output = scpClient.put(fileName, expected.length, remotePath, mode)) {
                output.write(expected);
            }

            assertTrue("Remote file not created: " + remoteFile, Files.exists(remoteFile));
            byte[] remoteData = Files.readAllBytes(remoteFile);
            assertArrayEquals("Mismatched remote put data", expected, remoteData);

            Arrays.fill(remoteData, (byte) 0); // make sure we start with a clean slate
            try (InputStream input = scpClient.get(remotePath + "/" + fileName)) {
                int readLen = input.read(remoteData);
                assertEquals("Mismatched remote get data size", expected.length, readLen);
                // make sure we reached EOF
                assertEquals("Unexpected extra data after read expected size", -1, input.read());
            }

            assertArrayEquals("Mismatched remote get data", expected, remoteData);
        } finally {
            conn.close();
        }
    }

    protected String readFile(com.jcraft.jsch.Session session, String path, Path target) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel(Channel.CHANNEL_EXEC);
        c.setCommand("scp -f " + path);
        c.connect();

        String fileName = Objects.toString(target.getFileName(), null);
        try (OutputStream os = c.getOutputStream();
             InputStream is = c.getInputStream()) {

            os.write(0);
            os.flush();

            String header = ScpIoUtils.readLine(is, false);
            String expHeader
                    = ScpReceiveFileCommandDetails.COMMAND_NAME + ScpReceiveFileCommandDetails.DEFAULT_FILE_OCTAL_PERMISSIONS
                      + " " + Files.size(target) + " " + fileName;
            assertEquals("Mismatched header for " + path, expHeader, header);

            String lenValue = header.substring(6, header.indexOf(' ', 6));
            int length = Integer.parseInt(lenValue);
            os.write(0);
            os.flush();

            byte[] buffer = new byte[length];
            length = is.read(buffer, 0, buffer.length);
            assertEquals("Mismatched read data length for " + path, length, buffer.length);
            assertAckReceived(is, "Read data of " + path);

            os.write(0);
            os.flush();

            return new String(buffer, StandardCharsets.UTF_8);
        } finally {
            c.disconnect();
        }
    }

    protected String readDir(com.jcraft.jsch.Session session, String path, Path target) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel(Channel.CHANNEL_EXEC);
        c.setCommand("scp -r -f " + path);
        c.connect();

        try (OutputStream os = c.getOutputStream();
             InputStream is = c.getInputStream()) {
            ScpAckInfo.sendOk(os);

            String header = ScpIoUtils.readLine(is, false);
            String expPrefix = ScpReceiveDirCommandDetails.COMMAND_NAME
                               + ScpReceiveDirCommandDetails.DEFAULT_DIR_OCTAL_PERMISSIONS + " 0 ";
            assertTrue("Bad header prefix for " + path + ": " + header, header.startsWith(expPrefix));
            ScpAckInfo.sendOk(os);

            header = ScpIoUtils.readLine(is, false);
            String fileName = Objects.toString(target.getFileName(), null);
            String expHeader
                    = ScpReceiveFileCommandDetails.COMMAND_NAME + ScpReceiveFileCommandDetails.DEFAULT_FILE_OCTAL_PERMISSIONS
                      + " " + Files.size(target) + " " + fileName;
            assertEquals("Mismatched dir header for " + path, expHeader, header);
            int length = Integer.parseInt(header.substring(6, header.indexOf(' ', 6)));
            ScpAckInfo.sendOk(os);

            byte[] buffer = new byte[length];
            length = is.read(buffer, 0, buffer.length);
            assertEquals("Mismatched read buffer size for " + path, length, buffer.length);
            assertAckReceived(is, "Read date of " + path);

            ScpAckInfo.sendOk(os);

            header = ScpIoUtils.readLine(is, false);
            assertEquals("Mismatched end value for " + path, "E", header);
            ScpAckInfo.sendOk(os);

            return new String(buffer, StandardCharsets.UTF_8);
        } finally {
            c.disconnect();
        }
    }

    protected void readFileError(com.jcraft.jsch.Session session, String path) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel(Channel.CHANNEL_EXEC);
        String command = "scp -f " + path;
        c.setCommand(command);
        c.connect();

        try (OutputStream os = c.getOutputStream();
             InputStream is = c.getInputStream()) {

            ScpAckInfo.sendOk(os);
            assertEquals("Mismatched response for command: " + command, ScpAckInfo.ERROR, is.read());
        } finally {
            c.disconnect();
        }
    }

    protected void sendFile(com.jcraft.jsch.Session session, String path, Path target, String data) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel(Channel.CHANNEL_EXEC);
        String command = "scp -t " + path;
        c.setCommand(command);
        c.connect();

        try (OutputStream os = c.getOutputStream();
             InputStream is = c.getInputStream()) {

            assertAckReceived(is, command);

            Path parent = target.getParent();
            Collection<PosixFilePermission> perms = IoUtils.getPermissions(parent);
            String octalPerms = ScpPathCommandDetailsSupport.getOctalPermissions(perms);
            String name = Objects.toString(target.getFileName(), null);
            assertAckReceived(os, is,
                    ScpReceiveFileCommandDetails.COMMAND_NAME + octalPerms + " " + data.length() + " " + name);

            os.write(data.getBytes(StandardCharsets.UTF_8));
            os.flush();
            assertAckReceived(is, "Sent data (length=" + data.length() + ") for " + path + "[" + name + "]");

            ScpAckInfo.sendOk(os);

            Thread.sleep(100);
        } finally {
            c.disconnect();
        }
    }

    protected void assertAckReceived(OutputStream os, InputStream is, String command) throws IOException {
        ScpIoUtils.writeLine(os, command);
        assertAckReceived(is, command);
    }

    protected void assertAckReceived(InputStream is, String command) throws IOException {
        assertEquals("No ACK for command=" + command, 0, is.read());
    }

    protected void sendFileError(com.jcraft.jsch.Session session, String path, String name, String data) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel(Channel.CHANNEL_EXEC);
        String command = "scp -t " + path;
        c.setCommand(command);
        c.connect();

        try (OutputStream os = c.getOutputStream();
             InputStream is = c.getInputStream()) {

            assertAckReceived(is, command);

            command = "C7777 " + data.length() + " " + name;
            ScpIoUtils.writeLine(os, command);
            assertEquals("Mismatched response for command=" + command, ScpAckInfo.ERROR, is.read());
        } finally {
            c.disconnect();
        }
    }

    protected void sendDir(com.jcraft.jsch.Session session, String path, String dirName, String fileName, String data)
            throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel(Channel.CHANNEL_EXEC);
        String command = "scp -t -r " + path;
        c.setCommand(command);
        c.connect();

        try (OutputStream os = c.getOutputStream();
             InputStream is = c.getInputStream()) {

            assertAckReceived(is, command);
            assertAckReceived(os, is, "D0755 0 " + dirName);
            assertAckReceived(os, is, "C7777 " + data.length() + " " + fileName);

            os.write(data.getBytes(StandardCharsets.UTF_8));
            os.flush();
            assertAckReceived(is, "Send data of " + path);

            ScpAckInfo.sendOk(os);
            ScpIoUtils.writeLine(os, ScpDirEndCommandDetails.HEADER);
            assertAckReceived(is, "Signal end of " + path);
        } finally {
            c.disconnect();
        }
    }
}
