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

package org.apache.sshd.sftp.server;

import java.util.Collection;
import java.util.concurrent.CopyOnWriteArraySet;

import org.apache.sshd.common.util.EventListenerUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSftpEventListenerManager implements SftpEventListenerManager {
    private final Collection<SftpEventListener> sftpEventListeners = new CopyOnWriteArraySet<>();
    private final SftpEventListener sftpEventListenerProxy;

    protected AbstractSftpEventListenerManager() {
        sftpEventListenerProxy = EventListenerUtils.proxyWrapper(SftpEventListener.class, sftpEventListeners);
    }

    public Collection<SftpEventListener> getRegisteredListeners() {
        return sftpEventListeners;
    }

    @Override
    public SftpEventListener getSftpEventListenerProxy() {
        return sftpEventListenerProxy;
    }

    @Override
    public boolean addSftpEventListener(SftpEventListener listener) {
        return sftpEventListeners.add(SftpEventListener.validateListener(listener));
    }

    @Override
    public boolean removeSftpEventListener(SftpEventListener listener) {
        if (listener == null) {
            return false;
        }

        return sftpEventListeners.remove(SftpEventListener.validateListener(listener));
    }
}
