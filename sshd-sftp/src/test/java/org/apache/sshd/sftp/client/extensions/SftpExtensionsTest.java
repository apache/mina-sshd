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

package org.apache.sshd.sftp.client.extensions;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;
import java.util.stream.Collectors;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.subsystem.SubsystemFactory;
import org.apache.sshd.sftp.client.AbstractSftpClientTestSupport;
import org.apache.sshd.sftp.client.RawSftpClient;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.Attributes;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.server.SftpFileSystemAccessor;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.apache.sshd.sftp.server.SftpSubsystemProxy;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.testcontainers.shaded.com.google.common.base.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestMethodOrder(MethodName.class)
public class SftpExtensionsTest extends AbstractSftpClientTestSupport {
    public SftpExtensionsTest() throws IOException {
        super();
    }

    // see SSHD-890
    @Test
    void unsupportedExtension() throws IOException {
        try (SftpClient sftpClient = createSingleSessionClient()) {
            RawSftpClient sftp = assertObjectInstanceOf("Not a raw SFTP client", RawSftpClient.class, sftpClient);

            String opcode = getCurrentTestName();
            Buffer buffer = new ByteArrayBuffer(Integer.BYTES + GenericUtils.length(opcode) + Byte.SIZE, false);
            buffer.putString(opcode);

            int cmd = sftp.send(SftpConstants.SSH_FXP_EXTENDED, buffer);
            Buffer responseBuffer = sftp.receive(cmd);

            responseBuffer.getInt(); // Ignoring length
            int type = responseBuffer.getUByte();
            responseBuffer.getInt(); // Ignoring message ID
            int substatus = responseBuffer.getInt();

            assertEquals(SftpConstants.SSH_FXP_STATUS, type, "Type is not STATUS");
            assertEquals(SftpConstants.SSH_FX_OP_UNSUPPORTED, substatus, "Sub-Type is not UNSUPPORTED");
        }
    }

    // see SSHD-1166
    @Test
    void customFileExtensionAttributes() throws IOException {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path localFile = CommonTestSupportUtils.resolve(
                targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        Files.createDirectories(localFile.getParent());
        Files.write(localFile, Collections.singleton(getClass().getName() + "#" + getCurrentTestName() + "@" + new Date()),
                StandardCharsets.UTF_8);

        List<? extends SubsystemFactory> factories = sshd.getSubsystemFactories();
        assertEquals(1, GenericUtils.size(factories), "Mismatched subsystem factories count");

        SubsystemFactory f = factories.get(0);
        assertObjectInstanceOf("Not an SFTP subsystem factory", SftpSubsystemFactory.class, f);

        Map<String, String> expected = Collections.unmodifiableMap(
                MapEntryUtils.MapBuilder.<String, String> builder()
                        .put("test", getCurrentTestName())
                        .put("class", getClass().getSimpleName())
                        .put("package", getClass().getPackage().getName())
                        .build());

        SftpSubsystemFactory factory = (SftpSubsystemFactory) f;
        SftpFileSystemAccessor accessor = factory.getFileSystemAccessor();
        Attributes attrs;
        try {
            factory.setFileSystemAccessor(new SftpFileSystemAccessor() {
                @Override
                public NavigableMap<String, Object> resolveReportedFileAttributes(
                        SftpSubsystemProxy subsystem,
                        Path file, int flags, NavigableMap<String, Object> attrs, LinkOption... options)
                        throws IOException {
                    if (Objects.equal(file, localFile)) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> extra = (Map<String, Object>) attrs.get(IoUtils.EXTENDED_VIEW_ATTR);
                        if (MapEntryUtils.isEmpty(extra)) {
                            attrs.put(IoUtils.EXTENDED_VIEW_ATTR, expected);
                        } else {
                            extra.putAll(expected);
                        }
                    }
                    return attrs;
                }
            });

            try (SftpClient sftp = createSingleSessionClient()) {
                attrs = sftp.stat(CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, localFile));
            }

        } finally {
            factory.setFileSystemAccessor(accessor);    // restore original value
        }

        Map<String, byte[]> extsMap = attrs.getExtensions();
        assertTrue(MapEntryUtils.isNotEmpty(extsMap), "No extended attributes provided");

        Map<String, String> actual = extsMap.entrySet()
                .stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey, e -> new String(e.getValue(), StandardCharsets.UTF_8),
                        MapEntryUtils.throwingMerger(), () -> new TreeMap<>(String.CASE_INSENSITIVE_ORDER)));
        assertMapEquals(IoUtils.EXTENDED_VIEW_ATTR, expected, actual);
    }
}
