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

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collection;
import java.util.Set;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.scp.common.ScpTransferEventListener;
import org.apache.sshd.scp.common.helpers.ScpAckInfo;
import org.apache.sshd.scp.server.ScpCommandFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.AfterClass;
import org.junit.Before;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractScpTestSupport extends BaseTestSupport {
    @SuppressWarnings("checkstyle:anoninnerlength")
    protected static final ScpTransferEventListener DEBUG_LISTENER = new ScpTransferEventListener() {
        @Override
        public void startFolderEvent(
                Session s, FileOperation op, Path file, Set<PosixFilePermission> perms) {
            logEvent("starFolderEvent", s, op, file, false, -1L, perms, null);
        }

        @Override
        public void startFileEvent(
                Session s, FileOperation op, Path file, long length, Set<PosixFilePermission> perms) {
            logEvent("startFileEvent", s, op, file, true, length, perms, null);
        }

        @Override
        public void endFolderEvent(
                Session s, FileOperation op, Path file, Set<PosixFilePermission> perms, Throwable thrown) {
            logEvent("endFolderEvent", s, op, file, false, -1L, perms, thrown);
        }

        @Override
        public void endFileEvent(
                Session s, FileOperation op, Path file, long length, Set<PosixFilePermission> perms, Throwable thrown) {
            logEvent("endFileEvent", s, op, file, true, length, perms, thrown);
        }

        @Override
        public void handleFileEventAckInfo(
                Session session, FileOperation op, Path file, long length,
                Set<PosixFilePermission> perms, ScpAckInfo ackInfo)
                throws IOException {
            logEvent("ackInfo(" + ackInfo + ")", session, op, file, true, length, perms, null);
        }

        private void logEvent(
                String type, Session s, FileOperation op, Path path, boolean isFile,
                long length, Collection<PosixFilePermission> perms, Throwable t) {
            if (!OUTPUT_DEBUG_MESSAGES) {
                return; // just in case
            }
            StringBuilder sb = new StringBuilder(Byte.MAX_VALUE);
            sb.append("    ").append(type)
                    .append('[').append(s).append(']')
                    .append('[').append(op).append(']')
                    .append(' ').append(isFile ? "File" : "Directory").append('=').append(path)
                    .append(' ').append("length=").append(length)
                    .append(' ').append("perms=").append(perms);
            if (t != null) {
                sb.append(' ').append("ERROR=").append(t.getClass().getSimpleName()).append(": ").append(t.getMessage());
            }
            outputDebugMessage(sb.toString());
        }
    };

    protected static SshServer sshd;
    protected static int port;
    protected static SshClient client;

    protected final FileSystemFactory fileSystemFactory;

    protected AbstractScpTestSupport() {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        fileSystemFactory = new VirtualFileSystemFactory(parentPath);
    }

    protected static void setupClientAndServer(Class<?> anchor) throws Exception {
        // Need to use RSA since Ganymede/Jsch does not support EC
        SimpleGeneratorHostKeyProvider provider = new SimpleGeneratorHostKeyProvider();
        provider.setAlgorithm(KeyUtils.RSA_ALGORITHM);
        provider.setKeySize(1024);

        Path targetDir = CommonTestSupportUtils.detectTargetFolder(anchor);
        provider.setPath(targetDir.resolve(anchor.getSimpleName() + "-key"));
        sshd = CoreTestSupportUtils.setupTestFullSupportServer(anchor);
        sshd.setKeyPairProvider(provider);

        ScpCommandFactory factory = new ScpCommandFactory();
        sshd.setCommandFactory(factory);
        sshd.setShellFactory(factory);
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestFullSupportClient(anchor);
        client.start();
    }

    @AfterClass
    public static void tearDownClientAndServer() throws Exception {
        if (sshd != null) {
            try {
                sshd.stop(true);
            } finally {
                sshd = null;
            }
        }

        if (client != null) {
            try {
                client.stop();
            } finally {
                client = null;
            }
        }
    }

    protected ClientSession createClientSession() throws IOException {
        return createClientSession(client, port);
    }

    protected ClientSession createAuthenticatedClientSession() throws IOException {
        return createAuthenticatedClientSession(getCurrentTestName());
    }

    protected static ClientSession createAuthenticatedClientSession(String username) throws IOException {
        ClientSession session = client.connect(username, TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT)
                .getSession();
        try {
            session.addPasswordIdentity(username);
            session.auth().verify(AUTH_TIMEOUT);

            ClientSession result = session;
            session = null; // avoid auto-close at finally clause
            return result;
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }

    protected static ScpTransferEventListener getScpTransferEventListener(ClientSession session) {
        return OUTPUT_DEBUG_MESSAGES ? DEBUG_LISTENER : ScpTransferEventListener.EMPTY;
    }

    protected CloseableScpClient createCloseableScpClient() throws IOException {
        return createCloseableScpClient(getCurrentTestName());
    }

    protected CloseableScpClient createCloseableScpClient(String username) throws IOException {
        ClientSession session = createAuthenticatedClientSession(username);
        try {
            ScpClient client = createScpClient(session);
            CloseableScpClient closer = CloseableScpClient.singleSessionInstance(client);
            session = null; // avoid auto-close at finally clause
            return closer;
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }

    protected static ScpClient createScpClient(ClientSession session) {
        ScpClientCreator creator = ScpClientCreator.instance();
        ScpTransferEventListener listener = getScpTransferEventListener(session);
        return creator.createScpClient(session, listener);
    }

    @Before
    public void setUp() throws Exception {
        sshd.setFileSystemFactory(fileSystemFactory);
    }
}
