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

package org.apache.sshd.client.subsystem.sftp.extensions.helpers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.subsystem.sftp.AbstractSftpClientTestSupport;
import org.apache.sshd.client.subsystem.sftp.SftpClient;
import org.apache.sshd.client.subsystem.sftp.SftpClient.CloseableHandle;
import org.apache.sshd.client.subsystem.sftp.extensions.MD5FileExtension;
import org.apache.sshd.client.subsystem.sftp.extensions.MD5HandleExtension;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.subsystem.sftp.SftpException;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.Utils;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class)   // see https://github.com/junit-team/junit/wiki/Parameterized-tests
public class AbstractMD5HashExtensionTest extends AbstractSftpClientTestSupport {
    private static final List<Integer> DATA_SIZES =
            Collections.unmodifiableList(
                    Arrays.asList(
                            Integer.valueOf(Byte.MAX_VALUE),
                            Integer.valueOf(SftpConstants.MD5_QUICK_HASH_SIZE),
                            Integer.valueOf(IoUtils.DEFAULT_COPY_SIZE),
                            Integer.valueOf(Byte.SIZE * IoUtils.DEFAULT_COPY_SIZE)
                    ));

    private final int size;

    public AbstractMD5HashExtensionTest(int size) throws IOException {
        this.size = size;
    }

    @Parameters(name = "dataSize={0}")
    public static Collection<Object[]> parameters() {
        return parameterize(DATA_SIZES);
    }

    @BeforeClass
    public static void checkMD5Supported() {
        Assume.assumeTrue("MD5 not supported", BuiltinDigests.md5.isSupported());
    }

    @Before
    public void setUp() throws Exception {
        setupServer();
    }

    @After
    public void tearDown() throws Exception {
        tearDownServer();
    }

    @Test
    public void testMD5HashExtension() throws Exception {
        testMD5HashExtension(size);
    }

    private void testMD5HashExtension(int dataSize) throws Exception {
        byte[] seed = (getClass().getName() + "#" + getCurrentTestName() + "-" + dataSize + IoUtils.EOL).getBytes(StandardCharsets.UTF_8);
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(dataSize + seed.length)) {
            while (baos.size() < dataSize) {
                baos.write(seed);
            }

            testMD5HashExtension(baos.toByteArray());
        }
    }

    @SuppressWarnings("checkstyle:nestedtrydepth")
    private void testMD5HashExtension(byte[] data) throws Exception {
        Digest digest = BuiltinDigests.md5.create();
        digest.init();
        digest.update(data);

        byte[] expectedHash = digest.digest();
        byte[] quickHash = expectedHash;
        if (data.length > SftpConstants.MD5_QUICK_HASH_SIZE) {
            byte[] quickData = new byte[SftpConstants.MD5_QUICK_HASH_SIZE];
            System.arraycopy(data, 0, quickData, 0, quickData.length);
            digest = BuiltinDigests.md5.create();
            digest.init();
            digest.update(quickData);
            quickHash = digest.digest();
        }

        Path targetPath = detectTargetFolder();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName());
        Path srcFile = assertHierarchyTargetFolderExists(lclSftp).resolve("data-" + data.length + ".txt");
        Files.write(srcFile, data, IoUtils.EMPTY_OPEN_OPTIONS);

        Path parentPath = targetPath.getParent();
        String srcPath = Utils.resolveRelativeRemotePath(parentPath, srcFile);
        String srcFolder = Utils.resolveRelativeRemotePath(parentPath, srcFile.getParent());

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (SftpClient sftp = session.createSftpClient()) {
                    MD5FileExtension file = assertExtensionCreated(sftp, MD5FileExtension.class);
                    try {
                        byte[] actual = file.getHash(srcFolder, 0L, 0L, quickHash);
                        fail("Unexpected file success on folder=" + srcFolder + ": " + BufferUtils.toHex(':', actual));
                    } catch (IOException e) {    // expected - not allowed to hash a folder
                        assertTrue("Not an SftpException for file hash on " + srcFolder, e instanceof SftpException);
                    }

                    MD5HandleExtension hndl = assertExtensionCreated(sftp, MD5HandleExtension.class);
                    try (CloseableHandle dirHandle = sftp.openDir(srcFolder)) {
                        try {
                            byte[] actual = hndl.getHash(dirHandle, 0L, 0L, quickHash);
                            fail("Unexpected handle success on folder=" + srcFolder + ": " + BufferUtils.toHex(':', actual));
                        } catch (IOException e) {    // expected - not allowed to hash a folder
                            assertTrue("Not an SftpException for handle hash on " + srcFolder, e instanceof SftpException);
                        }
                    }

                    try (CloseableHandle fileHandle = sftp.open(srcPath, SftpClient.OpenMode.Read)) {
                        for (byte[] qh : new byte[][]{GenericUtils.EMPTY_BYTE_ARRAY, quickHash}) {
                            for (boolean useFile : new boolean[]{true, false}) {
                                byte[] actualHash = useFile ? file.getHash(srcPath, 0L, 0L, qh) : hndl.getHash(fileHandle, 0L, 0L, qh);
                                String type = useFile ? file.getClass().getSimpleName() : hndl.getClass().getSimpleName();
                                if (!Arrays.equals(expectedHash, actualHash)) {
                                    fail("Mismatched hash for quick=" + BufferUtils.toHex(':', qh)
                                            + " using " + type + " on " + srcFile
                                            + ": expected=" + BufferUtils.toHex(':', expectedHash)
                                            + ", actual=" + BufferUtils.toHex(':', actualHash));
                                }
                            }
                        }
                    }
                }
            } finally {
                client.stop();
            }
        }
    }
}
