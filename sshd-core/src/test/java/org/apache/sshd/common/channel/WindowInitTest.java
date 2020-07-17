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
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
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
@Category({ NoIoTestCase.class })
public class WindowInitTest extends BaseTestSupport {
    private static final AbstractChannel MOCK_CHANNEL = new AbstractChannel(true) {
        @Override
        public OpenFuture open(int recipient, long rwSize, long packetSize, Buffer buffer) {
            return null;
        }

        @Override
        public void handleOpenSuccess(int recipient, long rwSize, long packetSize, Buffer buffer) throws IOException {
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

    public WindowInitTest(long initialSize, long packetSize) {
        this.initialSize = initialSize;
        this.packetSize = packetSize;
    }

    @Parameters(name = "initial-size={0}, packet-size={1}")
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

    @Test(expected = IllegalArgumentException.class)
    public void testInitializationFailure() throws IOException {
        try (Window w = new Window(MOCK_CHANNEL, null, true, true)) {
            w.init(initialSize, packetSize, PropertyResolver.EMPTY);
            fail("Unexpected success for initialSize=" + initialSize + ", packetSize=" + packetSize);
        }
    }
}
