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
package org.apache.sshd.server.session;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.ServerFactoryManager;

/**
 * The default implementation for a {@link ServerSession}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ServerSessionImpl extends AbstractServerSession {
    public ServerSessionImpl(ServerFactoryManager server, IoSession ioSession) throws Exception {
        super(server, ioSession);
        signalSessionCreated(ioSession);

        String headerConfig = CoreModuleProperties.SERVER_EXTRA_IDENTIFICATION_LINES.getOrNull(this);
        String[] headers = GenericUtils.split(headerConfig, CoreModuleProperties.SERVER_EXTRA_IDENT_LINES_SEPARATOR);
        // We intentionally create a modifiable array so as to allow users to
        // modify it via SessionListener or ReservedSessionMessagesHandler
        List<String> extraLines = GenericUtils.isEmpty(headers)
                ? new ArrayList<>()
                : new ArrayList<>(Arrays.asList(headers));
        sendServerIdentification(extraLines);
    }
}
