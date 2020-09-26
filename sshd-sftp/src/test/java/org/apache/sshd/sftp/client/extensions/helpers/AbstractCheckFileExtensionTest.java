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

package org.apache.sshd.sftp.client.extensions.helpers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.digest.DigestFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.sftp.client.AbstractSftpClientTestSupport;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.CloseableHandle;
import org.apache.sshd.sftp.client.extensions.CheckFileHandleExtension;
import org.apache.sshd.sftp.client.extensions.CheckFileNameExtension;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpException;
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
public class AbstractCheckFileExtensionTest extends AbstractSftpClientTestSupport {
    private static final Collection<Integer> DATA_SIZES = Collections.unmodifiableList(
            Arrays.asList(
                    (int) Byte.MAX_VALUE,
                    SftpConstants.MIN_CHKFILE_BLOCKSIZE,
                    IoUtils.DEFAULT_COPY_SIZE,
                    Byte.SIZE * IoUtils.DEFAULT_COPY_SIZE));
    private static final Collection<Integer> BLOCK_SIZES = Collections.unmodifiableList(
            Arrays.asList(
                    0,
                    SftpConstants.MIN_CHKFILE_BLOCKSIZE,
                    1024,
                    IoUtils.DEFAULT_COPY_SIZE));
    private static final Collection<Object[]> PARAMETERS;

    static {
        Collection<Object[]> list = new ArrayList<>();
        for (DigestFactory factory : BuiltinDigests.VALUES) {
            if (!factory.isSupported()) {
                System.out.println("Skip unsupported digest=" + factory.getAlgorithm());
                continue;
            }

            String algorithm = factory.getName();
            for (Number dataSize : DATA_SIZES) {
                for (Number blockSize : BLOCK_SIZES) {
                    list.add(new Object[] { algorithm, dataSize, blockSize });
                }
            }
        }
        PARAMETERS = list;
    }

    private final String algorithm;
    private final int dataSize;
    private final int blockSize;

    public AbstractCheckFileExtensionTest(String algorithm, int dataSize, int blockSize) throws IOException {
        this.algorithm = algorithm;
        this.dataSize = dataSize;
        this.blockSize = blockSize;
    }

    @Parameters(name = "{0} - dataSize={1}, blockSize={2}")
    public static Collection<Object[]> parameters() {
        return PARAMETERS;
    }

    @Before
    public void setUp() throws Exception {
        setupServer();
    }

    @Test
    public void testCheckFileExtension() throws Exception {
        testCheckFileExtension(algorithm, dataSize, blockSize);
    }

    private void testCheckFileExtension(String expectedAlgorithm, int inputDataSize, int hashBlockSize) throws Exception {
        NamedFactory<? extends Digest> factory = BuiltinDigests.fromFactoryName(expectedAlgorithm);
        Digest digest = null;
        if (blockSize == 0) {
            digest = factory.create();
            digest.init();
        }

        byte[] seed = (getClass().getName() + "#" + getCurrentTestName()
                       + "-" + expectedAlgorithm
                       + "-" + inputDataSize + "/" + hashBlockSize
                       + IoUtils.EOL)
                               .getBytes(StandardCharsets.UTF_8);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(inputDataSize + seed.length)) {
            while (baos.size() < inputDataSize) {
                baos.write(seed);

                if (digest != null) {
                    digest.update(seed);
                }
            }

            testCheckFileExtension(factory, baos.toByteArray(), hashBlockSize, (digest == null) ? null : digest.digest());
        }
    }

    @SuppressWarnings("checkstyle:nestedtrydepth")
    private void testCheckFileExtension(
            NamedFactory<? extends Digest> factory, byte[] data, int hashBlockSize, byte[] expectedHash)
            throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp
                = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName());
        Path srcFile = assertHierarchyTargetFolderExists(lclSftp)
                .resolve(factory.getName() + "-data-" + data.length + "-" + hashBlockSize + ".txt");
        Files.write(srcFile, data, IoUtils.EMPTY_OPEN_OPTIONS);

        List<String> algorithms = new ArrayList<>(BuiltinDigests.VALUES.size());
        // put the selected algorithm 1st and then the rest
        algorithms.add(factory.getName());
        for (NamedFactory<? extends Digest> f : BuiltinDigests.VALUES) {
            if (f == factory) {
                continue;
            }

            algorithms.add(f.getName());
        }

        Path parentPath = targetPath.getParent();
        String srcPath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, srcFile);
        String srcFolder = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, srcFile.getParent());
        try (SftpClient sftp = createSingleSessionClient()) {
            CheckFileNameExtension file = assertExtensionCreated(sftp, CheckFileNameExtension.class);
            try {
                Map.Entry<String, ?> result = file.checkFileName(srcFolder, algorithms, 0L, 0L, hashBlockSize);
                fail("Unexpected success to hash folder=" + srcFolder + ": " + result.getKey());
            } catch (IOException e) { // expected - not allowed to hash a folder
                assertTrue("Not an SftpException", e instanceof SftpException);
            }

            CheckFileHandleExtension hndl = assertExtensionCreated(sftp, CheckFileHandleExtension.class);
            try (CloseableHandle dirHandle = sftp.openDir(srcFolder)) {
                try {
                    Map.Entry<String, ?> result = hndl.checkFileHandle(dirHandle, algorithms, 0L, 0L, hashBlockSize);
                    fail("Unexpected handle success on folder=" + srcFolder + ": " + result.getKey());
                } catch (IOException e) { // expected - not allowed to hash a folder
                    assertTrue("Not an SftpException", e instanceof SftpException);
                }
            }

            String hashAlgo = algorithms.get(0);
            validateHashResult(file, file.checkFileName(srcPath, algorithms, 0L, 0L, hashBlockSize), hashAlgo,
                    expectedHash);
            try (CloseableHandle fileHandle = sftp.open(srcPath, SftpClient.OpenMode.Read)) {
                validateHashResult(hndl, hndl.checkFileHandle(fileHandle, algorithms, 0L, 0L, hashBlockSize), hashAlgo,
                        expectedHash);
            }
        }
    }

    private void validateHashResult(
            NamedResource hasher, Map.Entry<String, ? extends Collection<byte[]>> result,
            String expectedAlgorithm, byte[] expectedHash) {
        String name = hasher.getName();
        assertNotNull("No result for hash=" + name, result);
        assertEquals("Mismatched hash algorithms for " + name, expectedAlgorithm, result.getKey());

        if (NumberUtils.length(expectedHash) > 0) {
            Collection<byte[]> values = result.getValue();
            assertEquals("Mismatched hash values count for " + name, 1, GenericUtils.size(values));

            byte[] actualHash = GenericUtils.head(values);
            if (!Arrays.equals(expectedHash, actualHash)) {
                fail("Mismatched hashes for " + name
                     + ": expected=" + BufferUtils.toHex(':', expectedHash)
                     + ", actual=" + BufferUtils.toHex(':', expectedHash));
            }
        }
    }
}
