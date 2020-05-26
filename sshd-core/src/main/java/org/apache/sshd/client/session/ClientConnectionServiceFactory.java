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
package org.apache.sshd.client.session;

import java.io.IOException;

import org.apache.sshd.common.Service;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.forward.PortForwardingEventListener;
import org.apache.sshd.common.session.AbstractConnectionServiceFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientConnectionServiceFactory extends AbstractConnectionServiceFactory implements ServiceFactory {
    public static final ClientConnectionServiceFactory INSTANCE = new ClientConnectionServiceFactory() {
        @Override
        public void addPortForwardingEventListener(PortForwardingEventListener listener) {
            throw new UnsupportedOperationException("addPortForwardingListener(" + listener + ") N/A on default instance");
        }

        @Override
        public void removePortForwardingEventListener(PortForwardingEventListener listener) {
            throw new UnsupportedOperationException(
                    "removePortForwardingEventListener(" + listener + ") N/A on default instance");
        }

        @Override
        public PortForwardingEventListener getPortForwardingEventListenerProxy() {
            return PortForwardingEventListener.EMPTY;
        }
    };

    public ClientConnectionServiceFactory() {
        super();
    }

    @Override
    public String getName() {
        return "ssh-connection";
    }

    @Override
    public Service create(Session session) throws IOException {
        AbstractClientSession abstractSession
                = ValidateUtils.checkInstanceOf(session, AbstractClientSession.class, "Not a client session: %s", session);
        ClientConnectionService service = new ClientConnectionService(abstractSession);
        service.addPortForwardingEventListenerManager(this);
        return service;
    }
}
