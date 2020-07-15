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
package org.apache.sshd.common.forward;

import java.util.Collection;
import java.util.concurrent.CopyOnWriteArraySet;

import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.util.EventListenerUtils;

/**
 * The default {@link ForwarderFactory} implementation.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultForwarderFactory implements ForwarderFactory, PortForwardingEventListenerManager {
    public static final DefaultForwarderFactory INSTANCE = new DefaultForwarderFactory() {
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

    private final Collection<PortForwardingEventListener> listeners = new CopyOnWriteArraySet<>();
    private final PortForwardingEventListener listenerProxy;

    public DefaultForwarderFactory() {
        listenerProxy = EventListenerUtils.proxyWrapper(PortForwardingEventListener.class, listeners);
    }

    @Override
    public PortForwardingEventListener getPortForwardingEventListenerProxy() {
        return listenerProxy;
    }

    @Override
    public void addPortForwardingEventListener(PortForwardingEventListener listener) {
        listeners.add(PortForwardingEventListener.validateListener(listener));
    }

    @Override
    public void removePortForwardingEventListener(PortForwardingEventListener listener) {
        if (listener == null) {
            return;
        }

        listeners.remove(PortForwardingEventListener.validateListener(listener));
    }

    @Override
    public Forwarder create(ConnectionService service) {
        Forwarder forwarder = new DefaultForwarder(service);
        forwarder.addPortForwardingEventListenerManager(this);
        return forwarder;
    }
}
