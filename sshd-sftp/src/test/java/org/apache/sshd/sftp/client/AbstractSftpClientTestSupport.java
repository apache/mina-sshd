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
import java.nio.file.Path;
import java.util.Collections;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.sftp.client.extensions.SftpClientExtension;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.apache.sshd.util.test.JSchLogger;
import org.junit.AfterClass;
import org.junit.BeforeClass;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSftpClientTestSupport extends BaseTestSupport {
    protected static SshServer sshd;
    protected static int port;
    protected static SshClient client;

    protected final FileSystemFactory fileSystemFactory;

    protected AbstractSftpClientTestSupport() throws IOException {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        fileSystemFactory = new VirtualFileSystemFactory(parentPath);
    }

    @BeforeClass
    public static void setupClientAndServer() throws Exception {
        JSchLogger.init();
        sshd = CoreTestSupportUtils.setupTestFullSupportServer(AbstractSftpClientTestSupport.class);
        sshd.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory()));
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestClient(AbstractSftpClientTestSupport.class);
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

    protected void setupServer() throws Exception {
        sshd.setFileSystemFactory(fileSystemFactory);
    }

    protected ClientSession createAuthenticatedClientSession() throws IOException {
        return createAuthenticatedClientSession(client, port);
    }

    protected SftpClient createSingleSessionClient() throws IOException {
        ClientSession session = createAuthenticatedClientSession();
        try {
            SftpClient client = createSftpClient(session);
            try {
                SftpClient closer = client.singleSessionInstance();
                // avoid auto-close at finally clause
                client = null;
                session = null;
                return closer;
            } finally {
                if (client != null) {
                    client.close();
                }
            }
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }

    protected SftpClient createSftpClient(ClientSession session) throws IOException {
        return SftpClientFactory.instance().createSftpClient(session);
    }

    protected SftpClient createSftpClient(ClientSession session, int selector) throws IOException {
        return SftpClientFactory.instance().createSftpClient(session, selector);
    }

    protected static <E extends SftpClientExtension> E assertExtensionCreated(SftpClient sftp, Class<E> type) {
        E instance = sftp.getExtension(type);
        assertNotNull("Extension not created: " + type.getSimpleName(), instance);
        assertTrue("Extension not supported: " + instance.getName(), instance.isSupported());
        return instance;
    }
}
