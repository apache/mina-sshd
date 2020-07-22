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

package org.apache.sshd.common.io.nio2;

import java.io.Flushable;
import java.net.Socket;
import java.net.SocketOption;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.Property;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.session.ServerSessionImpl;
import org.apache.sshd.server.session.SessionFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class Nio2ServiceTest extends BaseTestSupport {
    public Nio2ServiceTest() {
        super();
    }

    @Test // see SSHD-554, SSHD-722
    public void testSetSocketOptions() throws Exception {
        try (SshServer sshd = setupTestServer()) {
            Map<Property<?>, Object> expectedOptions = new LinkedHashMap<>();
            expectedOptions.put(CoreModuleProperties.SOCKET_KEEPALIVE, true);
            expectedOptions.put(CoreModuleProperties.SOCKET_LINGER, 5);
            expectedOptions.put(CoreModuleProperties.SOCKET_RCVBUF, 1024);
            expectedOptions.put(CoreModuleProperties.SOCKET_REUSEADDR, true);
            expectedOptions.put(CoreModuleProperties.SOCKET_SNDBUF, 1024);
            expectedOptions.put(CoreModuleProperties.TCP_NODELAY, true);
            for (Map.Entry<Property<?>, ?> oe : expectedOptions.entrySet()) {
                PropertyResolverUtils.updateProperty(sshd, oe.getKey().getName(), oe.getValue());
            }

            Semaphore sigSem = new Semaphore(0, true);
            Map<SocketOption<?>, Map.Entry<?, ?>> actualOptionValues = new HashMap<>(expectedOptions.size());
            sshd.setSessionFactory(new SessionFactory(sshd) {
                @Override
                protected ServerSessionImpl doCreateSession(IoSession ioSession) throws Exception {
                    validateSocketOptions(ioSession);
                    sigSem.release();
                    return super.doCreateSession(ioSession);
                }

                private void validateSocketOptions(IoSession ioSession) throws Exception {
                    if (!(ioSession instanceof Nio2Session)) {
                        return;
                    }

                    AsynchronousSocketChannel socket = ((Nio2Session) ioSession).getSocket();
                    Collection<? extends SocketOption<?>> supported = socket.supportedOptions();
                    if (GenericUtils.isEmpty(supported)) {
                        return;
                    }

                    for (Map.Entry<Property<?>, ?> oe : expectedOptions.entrySet()) {
                        Property<?> prop = oe.getKey();
                        Object expValue = oe.getValue();
                        Map.Entry<SocketOption<?>, ?> optionEntry = Nio2Service.CONFIGURABLE_OPTIONS.get(prop);
                        SocketOption<?> option = optionEntry.getKey();
                        if (!supported.contains(option)) {
                            continue;
                        }

                        Object actValue = socket.getOption(option);
                        actualOptionValues.put(option, new SimpleImmutableEntry<>(expValue, actValue));
                    }
                }
            });
            sshd.start();
            int port = sshd.getPort();
            long startTime = System.nanoTime();
            try (Socket s = new Socket(TEST_LOCALHOST, port)) {
                long endTime = System.nanoTime();
                long duration = endTime - startTime;
                assertTrue("Connect duration is too high: " + duration, duration <= TimeUnit.SECONDS.toNanos(15L));
                assertTrue("Validation not completed on time", sigSem.tryAcquire(15L, TimeUnit.SECONDS));
            } finally {
                sshd.stop();
            }

            // NOTE: we do not fail the test since some O/S implementations treat the value as a recommendation - i.e.,
            // they might ignore it
            for (Map.Entry<SocketOption<?>, ? extends Map.Entry<?, ?>> mme : actualOptionValues.entrySet()) {
                SocketOption<?> option = mme.getKey();
                Map.Entry<?, ?> vp = mme.getValue();
                Object expValue = vp.getKey();
                Object actValue = vp.getValue();
                Appendable output = Objects.equals(expValue, actValue) ? System.out : System.err;
                output.append('\t').append(option.name())
                        .append(": expected=").append(Objects.toString(expValue))
                        .append(", actual=").append(Objects.toString(actValue))
                        .append(System.lineSeparator());
                if (output instanceof Flushable) {
                    ((Flushable) output).flush();
                }
            }
        }
    }
}
