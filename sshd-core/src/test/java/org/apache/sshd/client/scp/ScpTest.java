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
package org.apache.sshd.client.scp;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.SshServer;
import org.apache.sshd.client.scp.ScpClient;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.root.RootedFileSystemProvider;
import org.apache.sshd.common.scp.ScpHelper;
import org.apache.sshd.common.scp.ScpTransferEventListener;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.util.BaseTestSupport;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.JSchLogger;
import org.apache.sshd.util.SimpleUserInfo;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.ethz.ssh2.Connection;
import ch.ethz.ssh2.SCPClient;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;

/**
 * Test for SCP support.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpTest extends BaseTestSupport {

    private SshServer sshd;
    private int port;
    private com.jcraft.jsch.Session session;
    private final FileSystemFactory fileSystemFactory;

    public ScpTest() throws IOException {
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
        sshd.setCommandFactory(new ScpCommandFactory());
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
        sshd.setFileSystemFactory(fileSystemFactory);
        sshd.start();
        port = sshd.getPort();
    }

    protected com.jcraft.jsch.Session getJschSession() throws JSchException {
        JSchLogger.init();
        JSch sch = new JSch();
        session = sch.getSession("sshd", "localhost", port);
        session.setUserInfo(new SimpleUserInfo("sshd"));
        session.connect();
        return session;
    }

    @After
    public void tearDown() throws Exception {
        if (session != null) {
            session.disconnect();
        }
        
        if (sshd != null) {
            sshd.stop(true);
        }
    }

    @Test
    @Ignore
    public void testExternal() throws Exception {
        System.out.println("Scp available on port " + port);
        Thread.sleep(5 * 60000);
    }

    @Test
    public void testUploadAbsoluteDriveLetter() throws Exception {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();

            try {
                try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).await().getSession()) {
                    session.addPasswordIdentity(getCurrentTestName());
                    session.auth().verify(5L, TimeUnit.SECONDS);

                    ScpClient scp = createScpClient(session);
                    Path targetPath = detectTargetFolder().toPath();
                    Path parentPath = targetPath.getParent();
                    Path scpRoot = Utils.resolve(targetPath, ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName());
                    Utils.deleteRecursive(scpRoot);

                    Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
                    Path localFile = localDir.resolve(getCurrentTestName() + "-1.txt");
                    byte[] data = writeFile(localFile, (getCurrentTestName() + "\n"));

                    Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
                    Path remoteFile = remoteDir.resolve(localFile.getFileName().toString());
                    String localPath = localFile.toString();
                    String remotePath = Utils.resolveRelativeRemotePath(parentPath, remoteFile);
                    scp.upload(localPath, remotePath);
                    assertFileLength(remoteFile, data.length, 5000);

                    Path secondRemote = remoteDir.resolve(getCurrentTestName() + "-2.txt");
                    String secondPath = Utils.resolveRelativeRemotePath(parentPath, secondRemote);
                    scp.upload(localPath, secondPath);
                    assertFileLength(secondRemote, data.length, 5000);
                    
                    Path pathRemote = remoteDir.resolve(getCurrentTestName() + "-path.txt");
                    String pathPath = Utils.resolveRelativeRemotePath(parentPath, pathRemote);
                    scp.upload(localFile, pathPath);
                    assertFileLength(pathRemote, data.length, 5000);
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testScpUploadOverwrite() throws Exception {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();

            try {
                try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).await().getSession()) {
                    session.addPasswordIdentity(getCurrentTestName());
                    session.auth().verify(5L, TimeUnit.SECONDS);

                    ScpClient scp = createScpClient(session);
                    String data = getCurrentTestName() + "\n";

                    Path targetPath = detectTargetFolder().toPath();
                    Path parentPath = targetPath.getParent();
                    Path scpRoot = Utils.resolve(targetPath, ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName());
                    Utils.deleteRecursive(scpRoot);

                    Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
                    Path localFile = localDir.resolve(getCurrentTestName() + ".txt");
                    writeFile(localFile, data);

                    Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
                    Path remoteFile = remoteDir.resolve(localFile.getFileName());
                    writeFile(remoteFile, data + data);

                    String remotePath = Utils.resolveRelativeRemotePath(parentPath, remoteFile);
                    scp.upload(localFile.toString(), remotePath);
                    assertFileLength(remoteFile, data.length(), 5000);
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testScpUploadZeroLengthFile() throws Exception {
        Path targetPath = detectTargetFolder().toPath();
        Path scpRoot = Utils.resolve(targetPath, ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName());
        Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
        Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
        Path zeroLocal = localDir.resolve(getCurrentTestName());

        try (FileChannel fch = FileChannel.open(zeroLocal, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            if (fch.size() > 0L) {
                fch.truncate(0L);
            }
        }
        assertEquals("Non-zero size for local file=" + zeroLocal, 0L, Files.size(zeroLocal));

        Path zeroRemote = remoteDir.resolve(zeroLocal.getFileName());
        if (Files.exists(zeroRemote)) {
            Files.delete(zeroRemote);
        }

        try (SshClient client = SshClient.setUpDefaultClient()) {
            try {
                client.start();

                try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).await().getSession()) {
                    session.addPasswordIdentity(getCurrentTestName());
                    session.auth().verify(5L, TimeUnit.SECONDS);

                    ScpClient scp = createScpClient(session);
                    String remotePath = Utils.resolveRelativeRemotePath(targetPath.getParent(), zeroRemote);
                    scp.upload(zeroLocal.toString(), remotePath);
                    assertFileLength(zeroRemote, 0L, TimeUnit.SECONDS.toMillis(5L));
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testScpDownloadZeroLengthFile() throws Exception {
        Path targetPath = detectTargetFolder().toPath();
        Path scpRoot = Utils.resolve(targetPath, ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName());
        Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
        Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
        Path zeroLocal = localDir.resolve(getCurrentTestName());
        if (Files.exists(zeroLocal)) {
            Files.delete(zeroLocal);
        }

        Path zeroRemote = remoteDir.resolve(zeroLocal.getFileName());
        try (FileChannel fch = FileChannel.open(zeroRemote, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            if (fch.size() > 0L) {
                fch.truncate(0L);
            }
        }
        assertEquals("Non-zero size for remote file=" + zeroRemote, 0L, Files.size(zeroRemote));

        try (SshClient client = SshClient.setUpDefaultClient()) {
            try {
                client.start();

                try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).await().getSession()) {
                    session.addPasswordIdentity(getCurrentTestName());
                    session.auth().verify(5L, TimeUnit.SECONDS);

                    ScpClient scp = createScpClient(session);
                    String remotePath = Utils.resolveRelativeRemotePath(targetPath.getParent(), zeroRemote);
                    scp.download(remotePath, zeroLocal.toString());
                    assertFileLength(zeroLocal, 0L, TimeUnit.SECONDS.toMillis(5L));
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testScpNativeOnSingleFile() throws Exception {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();

            try {
                try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).await().getSession()) {
                    session.addPasswordIdentity(getCurrentTestName());
                    session.auth().verify(5L, TimeUnit.SECONDS);

                    ScpClient scp = createScpClient(session);
                    String data = getCurrentTestName() + "\n";

                    Path targetPath = detectTargetFolder().toPath();
                    Path parentPath = targetPath.getParent();
                    Path scpRoot = Utils.resolve(targetPath, ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName());
                    Utils.deleteRecursive(scpRoot);

                    Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
                    Path localOutFile = localDir.resolve(getCurrentTestName() + "-1.txt");
                    writeFile(localOutFile, data);

                    Path remoteDir = scpRoot.resolve("remote");
                    Path remoteOutFile = remoteDir.resolve(localOutFile.getFileName());
                    assertFalse("Remote folder already exists: " + remoteDir, Files.exists(remoteDir));
                    
                    String localOutPath = localOutFile.toString();
                    String remoteOutPath = Utils.resolveRelativeRemotePath(parentPath, remoteOutFile);
                    try {
                        scp.upload(localOutPath, remoteOutPath);
                        fail("Expected IOException for 1st time " + remoteOutPath);
                    } catch(IOException e) {
                        // ok
                    }
                    
                    Files.createDirectories(remoteDir);
                    scp.upload(localOutPath, remoteOutPath);
                    assertFileLength(remoteOutFile, data.length(), 5000);

                    Path secondLocal = localDir.resolve(localOutFile.getFileName());
                    scp.download(remoteOutPath, Utils.resolveRelativeRemotePath(parentPath, secondLocal));
                    assertFileLength(secondLocal, data.length(), 5000);
                    
                    Path localPath = localDir.resolve(getCurrentTestName() + "-path.txt");
                    scp.download(remoteOutPath, Utils.resolveRelativeRemotePath(parentPath, localPath));
                    assertFileLength(localPath, data.length(), 5000);
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testScpNativeOnMultipleFiles() throws Exception {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();

            try {
                try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).await().getSession()) {
                    session.addPasswordIdentity(getCurrentTestName());
                    session.auth().verify(5L, TimeUnit.SECONDS);

                    ScpClient scp = createScpClient(session);
                    Path targetPath = detectTargetFolder().toPath();
                    Path parentPath = targetPath.getParent();
                    Path scpRoot = Utils.resolve(targetPath, ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName());
                    Utils.deleteRecursive(scpRoot);

                    Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
                    Path local1 = localDir.resolve(getCurrentTestName() + "-1.txt");
                    byte[] data = writeFile(local1, getCurrentTestName() + "\n");

                    Path local2 = localDir.resolve(getCurrentTestName() + "-2.txt");
                    Files.write(local2, data);

                    Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
                    Path remote1 = remoteDir.resolve(local1.getFileName());
                    String remote1Path = Utils.resolveRelativeRemotePath(parentPath, remote1);
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
                    scp.upload(locals, Utils.resolveRelativeRemotePath(parentPath, remoteSubDir));
                    
                    Path remoteSub1 = remoteSubDir.resolve(local1.getFileName());
                    assertFileLength(remoteSub1, data.length, 5000);

                    Path remoteSub2 = remoteSubDir.resolve(local2.getFileName());
                    assertFileLength(remoteSub2, data.length, 5000);

                    String[] remotes = {
                            Utils.resolveRelativeRemotePath(parentPath, remoteSub1),
                            Utils.resolveRelativeRemotePath(parentPath, remoteSub2),
                        };

                    try {
                        scp.download(remotes, Utils.resolveRelativeRemotePath(parentPath, local1));
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

                    Files.createDirectories(localSubDir);
                    scp.download(remotes, localSubDir);

                    assertFileLength(localSubDir.resolve(remoteSub1.getFileName()), data.length, 5000);
                    assertFileLength(localSubDir.resolve(remoteSub2.getFileName()), data.length, 5000);
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testScpNativeOnRecursiveDirs() throws Exception {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).await().getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                ScpClient scp = createScpClient(session);
                Path targetPath = detectTargetFolder().toPath();
                Path parentPath = targetPath.getParent();
                Path scpRoot = Utils.resolve(targetPath, ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName());
                Utils.deleteRecursive(scpRoot);

                Path localDir = scpRoot.resolve("local");
                Path localSubDir = assertHierarchyTargetFolderExists(localDir.resolve("dir"));
                Path localSub1 = localSubDir.resolve(getCurrentTestName() + "-1.txt");
                byte[] data = writeFile(localSub1, getCurrentTestName() + "\n");
                Path localSub2 = localSubDir.resolve(getCurrentTestName() + "-2.txt");
                Files.write(localSub2, data);

                Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
                scp.upload(localSubDir, Utils.resolveRelativeRemotePath(parentPath, remoteDir), ScpClient.Option.Recursive);
                
                Path remoteSubDir = remoteDir.resolve(localSubDir.getFileName());
                assertFileLength(remoteSubDir.resolve(localSub1.getFileName()), data.length, 5000);
                assertFileLength(remoteSubDir.resolve(localSub2.getFileName()), data.length, 5000);

                Utils.deleteRecursive(localSubDir);

                scp.download(Utils.resolveRelativeRemotePath(parentPath, remoteSubDir), localDir, ScpClient.Option.Recursive);
                assertFileLength(localSub1, data.length, 5000);
                assertFileLength(localSub2, data.length, 5000);
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testScpNativeOnDirWithPattern() throws Exception {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).await().getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                ScpClient scp = createScpClient(session);
                Path targetPath = detectTargetFolder().toPath();
                Path parentPath = targetPath.getParent();
                Path scpRoot = Utils.resolve(targetPath, ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName());
                Utils.deleteRecursive(scpRoot);

                Path localDir = assertHierarchyTargetFolderExists(scpRoot.resolve("local"));
                Path local1 = localDir.resolve(getCurrentTestName() + "-1.txt");
                byte[] data = writeFile(local1, getCurrentTestName() + "\n");
                Path local2 = localDir.resolve(getCurrentTestName() + "-2.txt");
                Files.write(local2, data);

                Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
                String remotePath = Utils.resolveRelativeRemotePath(parentPath, remoteDir);
                scp.upload(localDir.toString() + File.separator + "*", remotePath);
                assertFileLength(remoteDir.resolve(local1.getFileName()), data.length, 5000);
                assertFileLength(remoteDir.resolve(local2.getFileName()), data.length, 5000);

                Files.delete(local1);
                Files.delete(local2);
                scp.download(remotePath + "/*", localDir);
                assertFileLength(local1, data.length, 5000);
                assertFileLength(local2, data.length, 5000);
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testScpNativeOnMixedDirAndFiles() throws Exception {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).await().getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                ScpClient scp = createScpClient(session);
                Path targetPath = detectTargetFolder().toPath();
                Path parentPath = targetPath.getParent();
                Path scpRoot = Utils.resolve(targetPath, ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName());
                Utils.deleteRecursive(scpRoot);

                Path localDir = scpRoot.resolve("local");
                Path localSubDir = assertHierarchyTargetFolderExists(localDir.resolve("dir"));
                Path local1 = localDir.resolve(getCurrentTestName() + "-1.txt");
                byte[] data = writeFile(local1, getCurrentTestName() + "\n");
                Path localSub2 = localSubDir.resolve(getCurrentTestName() + "-2.txt");
                Files.write(localSub2, data);

                Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
                String remotePath = Utils.resolveRelativeRemotePath(parentPath, remoteDir);
                scp.upload(localDir.toString() + File.separator + "*", remotePath, ScpClient.Option.Recursive);
                assertFileLength(remoteDir.resolve(local1.getFileName()), data.length, 5000);

                Path remoteSubDir = remoteDir.resolve(localSubDir.getFileName());
                assertFileLength(remoteSubDir.resolve(localSub2.getFileName()), data.length, 5000);

                Files.delete(local1);
                Utils.deleteRecursive(localSubDir);

                scp.download(remotePath + "/*", localDir);
                assertFileLength(local1, data.length, 5000);
                assertFalse("Unexpected recursive local file: " + localSub2, Files.exists(localSub2));

                Files.delete(local1);
                scp.download(remotePath + "/*", localDir, ScpClient.Option.Recursive);
                assertFileLength(local1, data.length, 5000);
                assertFileLength(localSub2, data.length, 5000);
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testScpNativePreserveAttributes() throws Exception {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).await().getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                ScpClient scp = createScpClient(session);
                Path targetPath = detectTargetFolder().toPath();
                Path parentPath = targetPath.getParent();
                Path scpRoot = Utils.resolve(targetPath, ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName());
                Utils.deleteRecursive(scpRoot);

                Path localDir = scpRoot.resolve("local");
                Path localSubDir = assertHierarchyTargetFolderExists(localDir.resolve("dir"));
                // convert everything to seconds since this is the SCP timestamps granularity
                long lastMod = TimeUnit.MILLISECONDS.toSeconds(Files.getLastModifiedTime(localSubDir).toMillis() - TimeUnit.DAYS.toMillis(1));
                Path local1 = localDir.resolve(getCurrentTestName() + "-1.txt");
                byte[] data = writeFile(local1, getCurrentTestName() + "\n");
                File lclFile1 = local1.toFile();
                lclFile1.setLastModified(lastMod);
                lclFile1.setExecutable(true, true);
                lclFile1.setWritable(false, false);

                Path localSub2 = localSubDir.resolve(getCurrentTestName() + "-2.txt");
                Files.write(localSub2, data);
                File lclSubFile2 = localSub2.toFile();
                lclSubFile2.setLastModified(lastMod);

                Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
                String remotePath = Utils.resolveRelativeRemotePath(parentPath, remoteDir);
                scp.upload(localDir.toString() + File.separator + "*", remotePath, ScpClient.Option.Recursive, ScpClient.Option.PreserveAttributes);

                Path remote1 = remoteDir.resolve(local1.getFileName());
                assertFileLength(remote1, data.length, 5000);
                
                File remFile1 = remote1.toFile();
                assertLastModifiedTimeEquals(remFile1, lastMod);

                Path remoteSubDir = remoteDir.resolve(localSubDir.getFileName());
                Path remoteSub2 = remoteSubDir.resolve(localSub2.getFileName());
                assertFileLength(remoteSub2, data.length, 5000);

                File remSubFile2 = remoteSub2.toFile();
                assertLastModifiedTimeEquals(remSubFile2, lastMod);

                Utils.deleteRecursive(localDir);
                Files.createDirectories(localDir);

                scp.download(remotePath + "/*", localDir, ScpClient.Option.Recursive, ScpClient.Option.PreserveAttributes);
                assertFileLength(local1, data.length, 5000);
                assertLastModifiedTimeEquals(lclFile1, lastMod);
                assertFileLength(localSub2, data.length, 5000);
                assertLastModifiedTimeEquals(lclSubFile2, lastMod);
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testStreamsUploadAndDownload() throws Exception {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).await().getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                ScpClient scp = createScpClient(session);
                Path targetPath = detectTargetFolder().toPath();
                Path parentPath = targetPath.getParent();
                Path scpRoot = Utils.resolve(targetPath, ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName());
                Utils.deleteRecursive(scpRoot);

                Path remoteDir = assertHierarchyTargetFolderExists(scpRoot.resolve("remote"));
                Path remoteFile = remoteDir.resolve(getCurrentTestName() + ".txt");
                String remotePath = Utils.resolveRelativeRemotePath(parentPath, remoteFile);
                byte[] data = (getClass().getName() + "#" + getCurrentTestName()).getBytes();
                scp.upload(data, remotePath, EnumSet.allOf(PosixFilePermission.class), null);

                byte[] uploaded = Files.readAllBytes(remoteFile);
                assertArrayEquals("Mismatched uploaded data", data, uploaded);

                byte[] downloaded = scp.downloadBytes(remotePath);
                assertArrayEquals("Mismatched downloaded data", uploaded, downloaded);
            } finally {
                client.stop();
            }
        }
    }

    // see http://stackoverflow.com/questions/2717936/file-createnewfile-creates-files-with-last-modified-time-before-actual-creatio
    // See https://msdn.microsoft.com/en-us/library/ms724290(VS.85).aspx
    // The NTFS file system delays updates to the last access time for a file by up to 1 hour after the last access
    private static void assertLastModifiedTimeEquals(File file, long expectedSeconds) {
        long actualSeconds = TimeUnit.MILLISECONDS.toSeconds(file.lastModified());
        if (OsUtils.isWin32()) {
            if (expectedSeconds != actualSeconds) {
                System.err.append("Mismatched last modified time for ").append(file.getAbsolutePath())
                          .append(" - expected=").append(String.valueOf(expectedSeconds))
                          .append(", actual=").println(actualSeconds);
            }
        } else {
            assertEquals("Mismatched last modified time for " + file.getAbsolutePath(), expectedSeconds, actualSeconds);
        }
    }

    private static byte[] writeFile(Path path, String data) throws IOException {
        try(OutputStream fos = Files.newOutputStream(path)) {
            byte[]  bytes = data.getBytes();
            fos.write(bytes);
            return bytes;
        }
    }

    @Test
    public void testJschScp() throws Exception {
        session = getJschSession();
        try {
            String data = getCurrentTestName() + "\n";
    
            String unixDir = "target/scp";
            String fileName = getCurrentTestName() + ".txt";
            String unixPath = unixDir + "/" + fileName;
            File root = new File(unixDir);
            File target = new File(unixPath);
            Utils.deleteRecursive(root);
            root.mkdirs();
            assertTrue(root.exists());
    
            target.delete();
            assertFalse(target.exists());
            sendFile(unixPath, fileName, data);
            assertFileLength(target, data.length(), 5000);
    
            target.delete();
            assertFalse(target.exists());
            sendFile(unixDir, fileName, data);
            assertFileLength(target, data.length(), 5000);
    
            sendFileError("target", ScpHelper.SCP_COMMAND_PREFIX, data);
    
            readFileError(unixDir);
    
            assertEquals("Mismatched file data", data, readFile(unixPath, target.length()));
            assertEquals("Mismatched dir data", data, readDir(unixDir, fileName, target.length()));
    
            target.delete();
            root.delete();
    
            sendDir("target", ScpHelper.SCP_COMMAND_PREFIX, fileName, data);
            assertFileLength(target, data.length(), 5000);
        } finally {
            session.disconnect();
        }
    }

    @Test
    public void testWithGanymede() throws Exception {
        // begin client config
        final Connection conn = new Connection("localhost", port);
        try {
            conn.connect(null, 5000, 0);
            conn.authenticateWithPassword("sshd", "sshd");
            final SCPClient scp_client = new SCPClient(conn);
            final Properties props = new Properties();
            props.setProperty("test", "test-passed");
            File f = new File("target/scp/gan");
            Utils.deleteRecursive(f);
            f.mkdirs();
            assertTrue(f.exists());
    
            String name = "test.properties";
            scp_client.put(toBytes(props, ""), name, "target/scp/gan");
            assertTrue(new File(f, name).exists());
            assertTrue(new File(f, name).delete());
    
            name = "test2.properties";
            scp_client.put(toBytes(props, ""), name, "target/scp/gan");
            assertTrue(new File(f, name).exists());
            assertTrue(new File(f, name).delete());
    
            assertTrue(f.delete());
        } finally {
            conn.close();
        }
    }

    private byte[] toBytes(final Properties properties, final String comments) {
        try(ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            properties.store(baos, comments);
            baos.close();
            return baos.toByteArray();
        } catch(IOException cause) {
            throw new RuntimeException("Failed to output properties to byte[]", cause);
        }
    }

    protected String readFile(String path, long expectedSize) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel("exec");
        c.setCommand("scp -f " + path);
        c.connect();

        int namePos = path.lastIndexOf('/');
        String fileName = (namePos >= 0) ? path.substring(namePos + 1) : path;
        try(OutputStream os = c.getOutputStream();
            InputStream is = c.getInputStream()) {

            os.write(0);
            os.flush();
            String header = readLine(is);
            assertEquals("Mismatched header for " + path, "C0644 " + expectedSize + " " + fileName, header);

            int length = Integer.parseInt(header.substring(6, header.indexOf(' ', 6)));
            os.write(0);
            os.flush();
    
            byte[] buffer = new byte[length];
            length = is.read(buffer, 0, buffer.length);
            assertEquals("Mismatched read data length for " + path, length, buffer.length);
            assertAckReceived(is, "Read data of " + path);

            os.write(0);
            os.flush();

            return new String(buffer);
        } finally {
            c.disconnect();
        }
    }

    protected String readDir(String path, String fileName, long expectedSize) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel("exec");
        c.setCommand("scp -r -f " + path);
        c.connect();

        try(OutputStream os = c.getOutputStream();
            InputStream is = c.getInputStream()) {
            os.write(0);
            os.flush();

            String header = readLine(is);
            assertTrue("Bad header prefix for " + path + ": " + header, header.startsWith("D0755 0 "));
            os.write(0);
            os.flush();

            header = readLine(is);
            assertEquals("Mismatched dir header for " + path, "C0644 " + expectedSize + " " + fileName, header);
            int length = Integer.parseInt(header.substring(6, header.indexOf(' ', 6)));
            os.write(0);
            os.flush();

            byte[] buffer = new byte[length];
            length = is.read(buffer, 0, buffer.length);
            assertEquals("Mismatched read buffer size for " + path, length, buffer.length);
            assertAckReceived(is, "Read date of " + path);

            os.write(0);
            os.flush();

            header = readLine(is);
            assertEquals("Mismatched end value for " + path, "E", header);
            os.write(0);
            os.flush();

            return new String(buffer);
        } finally {
            c.disconnect();
        }
    }

    protected String readFileError(String path) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel("exec");
        String command = "scp -f " + path; 
        c.setCommand(command);
        c.connect();

        try(OutputStream os = c.getOutputStream();
            InputStream is = c.getInputStream()) {
        
            os.write(0);
            os.flush();
            assertEquals("Mismatched response for command: " + command, 2, is.read());
            return null;
        } finally {
            c.disconnect();
        }
    }

    protected void sendFile(String path, String name, String data) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel("exec");
        String command = "scp -t " + path;
        c.setCommand(command);
        c.connect();

        try(OutputStream os = c.getOutputStream();
            InputStream is = c.getInputStream()) {

            assertAckReceived(is, command);
            assertAckReceived(os, is, "C7777 " + data.length() + " " + name); 

            os.write(data.getBytes());
            os.flush();
            assertAckReceived(is, "Sent data (length=" + data.length() + ") for " + path + "[" + name + "]");

            os.write(0);
            os.flush();

            Thread.sleep(100);
        } finally {
            c.disconnect();
        }
    }

    protected void assertAckReceived(OutputStream os, InputStream is, String command) throws IOException {
        os.write((command + "\n").getBytes());
        os.flush();
        assertAckReceived(is, command);
    }

    protected void assertAckReceived(InputStream is, String command) throws IOException {
        assertEquals("No ACK for command=" + command, 0, is.read());
    }

    protected void sendFileError(String path, String name, String data) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel("exec");
        String command = "scp -t " + path; 
        c.setCommand(command);
        c.connect();

        try(OutputStream os = c.getOutputStream();
            InputStream is = c.getInputStream()) {

            assertAckReceived(is, command);

            command = "C7777 " + data.length() + " " + name;
            os.write((command + "\n").getBytes());
            os.flush();
            assertEquals("Mismatched response for command=" + command, 2, is.read());
        } finally {
            c.disconnect();
        }
    }

    protected void sendDir(String path, String dirName, String fileName, String data) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel("exec");
        String command = "scp -t -r " + path;
        c.setCommand(command);
        c.connect();
        
        try(OutputStream os = c.getOutputStream();
            InputStream is = c.getInputStream()) {

            assertAckReceived(is, command);
            assertAckReceived(os, is, "D0755 0 " + dirName);
            assertAckReceived(os, is, "C7777 " + data.length() + " " + fileName);

            os.write(data.getBytes());
            os.flush();
            assertAckReceived(is, "Send data of " + path);

            os.write(0);
            os.flush();
            
            os.write("E\n".getBytes());
            os.flush();
            assertAckReceived(is, "Signal end of " + path);
        } finally {
            c.disconnect();
        }
    }

    private static String readLine(InputStream in) throws IOException {
        OutputStream baos = new ByteArrayOutputStream();
        try {
            for (; ; ) {
                int c = in.read();
                if (c == '\n') {
                    return baos.toString();
                } else if (c == -1) {
                    throw new IOException("End of stream");
                } else {
                    baos.write(c);
                }
            }
        } finally {
            baos.close();
        }
    }

    private ScpClient createScpClient(ClientSession session) {
        final Logger logger = LoggerFactory.getLogger(getClass().getName() + "[" + getCurrentTestName() + "]");
        return session.createScpClient(new ScpTransferEventListener() {
            @Override
            public void startFolderEvent(FileOperation op, Path file, Set<PosixFilePermission> perms) {
                logEvent("starFolderEvent", op, file, false, -1L, perms, null);
            }

            @Override
            public void startFileEvent(FileOperation op, Path file, long length, Set<PosixFilePermission> perms) {
                logEvent("startFileEvent", op, file, true, length, perms, null);

            }

            @Override
            public void endFolderEvent(FileOperation op, Path file, Set<PosixFilePermission> perms, Throwable thrown) {
                logEvent("endFolderEvent", op, file, false, -1L, perms, thrown);
            }

            @Override
            public void endFileEvent(FileOperation op, Path file, long length, Set<PosixFilePermission> perms, Throwable thrown) {
                logEvent("endFileEvent", op, file, true, length, perms, thrown);
            }

            private void logEvent(String type, FileOperation op, Path path, boolean isFile, long length, Collection<PosixFilePermission> perms, Throwable t) {
                StringBuilder sb = new StringBuilder(Byte.MAX_VALUE);
                sb.append('\t').append(type)
                        .append('[').append(op).append(']')
                        .append(' ').append(isFile ? "File" : "Directory").append('=').append(path)
                        .append(' ').append("length=").append(length)
                        .append(' ').append("perms=").append(perms)
                ;
                if (t != null) {
                    sb.append(' ').append("ERROR=").append(t.getClass().getSimpleName()).append(": ").append(t.getMessage());
                }
                logger.info(sb.toString());
            }
        });
    }
}
