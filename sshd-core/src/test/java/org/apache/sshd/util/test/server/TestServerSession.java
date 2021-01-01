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

package org.apache.sshd.util.test.server;

import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.session.ServerSessionImpl;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class TestServerSession extends ServerSessionImpl {
    public TestServerSession(ServerFactoryManager server, IoSession ioSession) throws Exception {
        super(server, ioSession);
    }

    @Override
    public void handleMessage(Buffer buffer) throws Exception {
        super.handleMessage(buffer); // debug breakpoint
    }
}
