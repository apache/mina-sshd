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
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
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
import org.apache.sshd.client.subsystem.sftp.extensions.CopyDataExtension;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.Utils;
import org.junit.After;
import org.junit.Before;
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
public class CopyDataExtensionImplTest extends AbstractSftpClientTestSupport {
    private static final List<Object[]> PARAMETERS =
            Collections.unmodifiableList(
                    Arrays.<Object[]>asList(
                            new Object[]{
                                    Integer.valueOf(IoUtils.DEFAULT_COPY_SIZE),
                                    Integer.valueOf(0),
                                    Integer.valueOf(IoUtils.DEFAULT_COPY_SIZE),
                                    Long.valueOf(0L)
                            },
                            new Object[]{
                                    Integer.valueOf(IoUtils.DEFAULT_COPY_SIZE),
                                    Integer.valueOf(IoUtils.DEFAULT_COPY_SIZE / 2),
                                    Integer.valueOf(IoUtils.DEFAULT_COPY_SIZE / 4),
                                    Long.valueOf(0L)
                            },
                            new Object[]{
                                    Integer.valueOf(IoUtils.DEFAULT_COPY_SIZE),
                                    Integer.valueOf(IoUtils.DEFAULT_COPY_SIZE / 2),
                                    Integer.valueOf(IoUtils.DEFAULT_COPY_SIZE / 4),
                                    Long.valueOf(IoUtils.DEFAULT_COPY_SIZE / 2)
                            },
                            new Object[]{
                                    Integer.valueOf(Byte.MAX_VALUE),
                                    Integer.valueOf(Byte.MAX_VALUE / 2),
                                    Integer.valueOf(Byte.MAX_VALUE),    // attempt to read more than available
                                    Long.valueOf(0L)
                            }
                    ));

    private int size;
    private int srcOffset;
    private int  length;
    private long dstOffset;

    public CopyDataExtensionImplTest(int size, int srcOffset, int length, long dstOffset) throws IOException {
        this.size = size;
        this.srcOffset = srcOffset;
        this.length = length;
        this.dstOffset = dstOffset;
    }

    @Parameters(name = "size={0}, readOffset={1}, readLength={2}, writeOffset={3}")
    public static Collection<Object[]> parameters() {
        return PARAMETERS;
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
    public void testCopyDataExtension() throws Exception {
        testCopyDataExtension(size, srcOffset, length, dstOffset);
    }

    private void testCopyDataExtension(int dataSize, int readOffset, int readLength, long writeOffset) throws Exception {
        byte[] seed = (getClass().getName() + "#" + getCurrentTestName()
                + "-" + dataSize
                + "-" + readOffset + "/" + readLength + "/" + writeOffset
                + IoUtils.EOL)
                .getBytes(StandardCharsets.UTF_8);
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(dataSize + seed.length)) {
            while (baos.size() < dataSize) {
                baos.write(seed);
            }

            testCopyDataExtension(baos.toByteArray(), readOffset, readLength, writeOffset);
        }
    }

    private void testCopyDataExtension(byte[] data, int readOffset, int readLength, long writeOffset) throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = Utils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName());
        LinkOption[] options = IoUtils.getLinkOptions(false);
        String baseName = readOffset + "-" + readLength + "-" + writeOffset;
        Path srcFile = assertHierarchyTargetFolderExists(lclSftp, options).resolve(baseName + "-src.txt");
        Files.write(srcFile, data, IoUtils.EMPTY_OPEN_OPTIONS);
        String srcPath = Utils.resolveRelativeRemotePath(parentPath, srcFile);

        Path dstFile = srcFile.getParent().resolve(baseName + "-dst.txt");
        if (Files.exists(dstFile, options)) {
            Files.delete(dstFile);
        }
        String dstPath = Utils.resolveRelativeRemotePath(parentPath, dstFile);

        try (SshClient client = setupTestClient()) {
            client.start();

            if (writeOffset > 0L) {
                Factory<? extends Random> factory = client.getRandomFactory();
                Random randomizer = factory.create();
                long totalLength = writeOffset + readLength;
                byte[] workBuf = new byte[(int) Math.min(totalLength, IoUtils.DEFAULT_COPY_SIZE)];
                try (OutputStream output = Files.newOutputStream(dstFile, IoUtils.EMPTY_OPEN_OPTIONS)) {
                    while (totalLength > 0L) {
                        randomizer.fill(workBuf);
                        output.write(workBuf);
                        totalLength -= workBuf.length;
                    }
                }
            }

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (SftpClient sftp = session.createSftpClient()) {
                    CopyDataExtension ext = assertExtensionCreated(sftp, CopyDataExtension.class);
                    try (CloseableHandle readHandle = sftp.open(srcPath, SftpClient.OpenMode.Read);
                         CloseableHandle writeHandle = sftp.open(dstPath, SftpClient.OpenMode.Write, SftpClient.OpenMode.Create)) {
                        ext.copyData(readHandle, readOffset, readLength, writeHandle, writeOffset);
                    }
                }
            } finally {
                client.stop();
            }
        }

        int available = data.length;
        int required = readOffset + readLength;
        if (required > available) {
            required = available;
        }
        byte[] expected = new byte[required - readOffset];
        System.arraycopy(data, readOffset, expected, 0, expected.length);

        byte[] actual = new byte[expected.length];
        try (FileChannel channel = FileChannel.open(dstFile, IoUtils.EMPTY_OPEN_OPTIONS)) {
            int readLen = channel.read(ByteBuffer.wrap(actual), writeOffset);
            assertEquals("Mismatched read data size", expected.length, readLen);
        }
        assertArrayEquals("Mismatched copy data", expected, actual);
    }
}
