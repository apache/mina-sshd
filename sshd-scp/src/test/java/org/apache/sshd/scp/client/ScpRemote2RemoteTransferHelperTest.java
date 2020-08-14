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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.scp.common.ScpHelper;
import org.apache.sshd.scp.common.ScpTimestamp;
import org.apache.sshd.scp.common.helpers.ScpReceiveFileCommandDetails;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ScpRemote2RemoteTransferHelperTest extends AbstractScpTestSupport {
    public ScpRemote2RemoteTransferHelperTest() {
        super();
    }

    @BeforeClass
    public static void setupClientAndServer() throws Exception {
        setupClientAndServer(ScpRemote2RemoteTransferHelperTest.class);
    }

    @Test
    public void testTransferFiles() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(scpRoot);    // start clean

        Path srcDir = assertHierarchyTargetFolderExists(scpRoot.resolve("srcdir"));
        Path srcFile = srcDir.resolve("source.txt");
        byte[] expectedData
                = CommonTestSupportUtils.writeFile(srcFile, getClass().getName() + "#" + getCurrentTestName() + IoUtils.EOL);
        String srcPath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, srcFile);

        Path dstDir = assertHierarchyTargetFolderExists(scpRoot.resolve("dstdir"));
        Path dstFile = dstDir.resolve("destination.txt");
        String dstPath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, dstFile);

        AtomicLong xferCount = new AtomicLong();
        try (ClientSession srcSession = createClientSession(getCurrentTestName() + "-src");
             ClientSession dstSession = createClientSession(getCurrentTestName() + "-dst")) {
            ScpRemote2RemoteTransferHelper helper = new ScpRemote2RemoteTransferHelper(
                    srcSession, dstSession, new ScpRemote2RemoteTransferListener() {
                        @Override
                        public void startDirectFileTransfer(
                                ClientSession srcSession, String source,
                                ClientSession dstSession, String destination,
                                ScpTimestamp timestamp, ScpReceiveFileCommandDetails details)
                                throws IOException {
                            assertEquals("Mismatched start xfer source path", srcPath, source);
                            assertEquals("Mismatched start xfer destination path", dstPath, destination);
                        }

                        @Override
                        public void endDirectFileTransfer(
                                ClientSession srcSession, String source,
                                ClientSession dstSession, String destination,
                                ScpTimestamp timestamp, ScpReceiveFileCommandDetails details,
                                long xferSize, Throwable thrown)
                                throws IOException {
                            assertEquals("Mismatched end xfer source path", srcPath, source);
                            assertEquals("Mismatched end xfer destination path", dstPath, destination);

                            long prev = xferCount.getAndSet(xferSize);
                            assertEquals("Mismatched 1st end file xfer size", 0L, prev);
                        }
                    });
            helper.transferFile(srcPath, dstPath, true);
        }
        assertEquals("Mismatched transfer size", expectedData.length, xferCount.getAndSet(0L));

        byte[] actualData = Files.readAllBytes(dstFile);
        assertArrayEquals("Mismatched transfer contents", expectedData, actualData);
    }

    private ClientSession createClientSession(String username) throws IOException {
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
}
