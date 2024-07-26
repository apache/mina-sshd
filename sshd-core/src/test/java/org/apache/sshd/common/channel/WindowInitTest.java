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
package org.apache.sshd.common.channel;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class WindowInitTest extends BaseTestSupport {
    private static final AbstractChannel MOCK_CHANNEL = new AbstractChannel(true) {
        @Override
        public OpenFuture open(long recipient, long rwSize, long packetSize, Buffer buffer) {
            return null;
        }

        @Override
        public void handleOpenSuccess(long recipient, long rwSize, long packetSize, Buffer buffer) throws IOException {
            // ignored
        }

        @Override
        public void handleOpenFailure(Buffer buffer) throws IOException {
            // ignored
        }

        @Override
        protected void doWriteData(byte[] data, int off, long len) throws IOException {
            // ignored
        }

        @Override
        protected void doWriteExtendedData(byte[] data, int off, long len) throws IOException {
            // ignored
        }
    };

    private long initialSize;
    private long packetSize;

    public void initWindowInitTest(long initialSize, long packetSize) {
        this.initialSize = initialSize;
        this.packetSize = packetSize;
    }

    public static List<Object[]> parameters() {
        List<Object[]> params = new ArrayList<>();
        params.add(new Object[] { -128L, CoreModuleProperties.MAX_PACKET_SIZE.getRequiredDefault() });
        params.add(
                new Object[] { BufferUtils.MAX_UINT32_VALUE + 1L, CoreModuleProperties.MAX_PACKET_SIZE.getRequiredDefault() });
        params.add(new Object[] { CoreModuleProperties.WINDOW_SIZE.getRequiredDefault(), 0L });
        params.add(new Object[] { CoreModuleProperties.WINDOW_SIZE.getRequiredDefault(), Byte.MIN_VALUE });
        params.add(new Object[] { CoreModuleProperties.WINDOW_SIZE.getRequiredDefault(), BufferUtils.MAX_UINT32_VALUE + 1L });
        params.add(new Object[] {
                CoreModuleProperties.WINDOW_SIZE.getRequiredDefault(),
                CoreModuleProperties.LIMIT_PACKET_SIZE.getRequiredDefault() + 1L });
        return params;
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "initial-size={0}, packet-size={1}")
    public void initializationFailure(long initialSize, long packetSize) throws IOException {
        initWindowInitTest(initialSize, packetSize);
        try (RemoteWindow w = new RemoteWindow(MOCK_CHANNEL, true)) {
            assertThrows(IllegalArgumentException.class, () -> w.init(initialSize, packetSize, PropertyResolver.EMPTY));
        }
    }
}
