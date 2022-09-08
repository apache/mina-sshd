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

package org.apache.sshd.mina;

import java.lang.reflect.Field;

import org.apache.mina.core.service.IoProcessor;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * Tests specific to the MINA connection back-end.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MinaSessionTest extends BaseTestSupport {

    public MinaSessionTest() {
        super();
    }

    private IoProcessor<?> getProcessor(AbstractFactoryManager manager) throws Exception {
        IoServiceFactory ioServiceFactory = manager.getIoServiceFactory();
        assertTrue("Unexpected type " + ioServiceFactory.getClass(), ioServiceFactory instanceof MinaServiceFactory);
        // Get the ioProcessor field
        Field f = MinaServiceFactory.class.getDeclaredField("ioProcessor");
        f.setAccessible(true);
        Object processor = f.get(ioServiceFactory);
        assertTrue("Unexpected type " + processor.getClass(), processor instanceof IoProcessor<?>);
        return (IoProcessor<?>) processor;
    }

    @Test
    public void testIoProcessorClosed() throws Exception {
        IoProcessor<?> ioProcessor = null;
        try (SshServer server = setupTestServer()) {
            server.start();
            try (SshClient client = setupTestClient()) {
                client.start();
                ioProcessor = getProcessor(client);
            }
            assertTrue("MINA client IoProcessor should be closed", ioProcessor.isDisposed() || ioProcessor.isDisposing());
            ioProcessor = getProcessor(server);
        }
        assertTrue("MINA server IoProcessor should be closed", ioProcessor.isDisposed() || ioProcessor.isDisposing());
    }
}
