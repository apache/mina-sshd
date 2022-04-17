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
package org.apache.sshd.common.session.helpers;

import java.util.Objects;

import org.apache.sshd.common.Service;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Holds the current SSH service for a {@link Session}.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CurrentService {

    /** The session this {@link CurrentService} belongs to. */
    protected final Session session;

    private String currentName;

    private Service currentService;

    /**
     * Creates a new {@link CurrentService} instance belonging to the given {@link Session}.
     *
     * @param session {@link Session} the instance belongs to
     */
    protected CurrentService(Session session) {
        this.session = Objects.requireNonNull(session, "No session given");
    }

    /**
     * Retrieves the name of the current service.
     *
     * @return the name, or {@code null} if none is set
     */
    public synchronized String getName() {
        return currentName;
    }

    /**
     * Retrieves the current service.
     *
     * @return the current service, or {@code null} if none is set
     */
    public synchronized Service getService() {
        return currentService;
    }

    /**
     * Sets the current service and its name, and optionally starts the service.
     *
     * @param service {@link Service} to set
     * @param name    Name of the service (the name of the {@link ServiceFactory} that created it)
     * @param start   whether to start the service
     */
    public void set(Service service, String name, boolean start) {
        ValidateUtils.checkNotNullAndNotEmpty(name, "No service name specified");
        Objects.requireNonNull(service, "No service specified");
        synchronized (this) {
            currentName = name;
            currentService = service;
        }
        if (start) {
            service.start();
        }
    }

    /**
     * Starts the current service.
     */
    public void start() {
        Service current = getService();
        ValidateUtils.checkState(current != null, "No current SSH service; cannot start");
        current.start();
    }

    /**
     * Processes a service request.
     *
     * @param  cmd       the command
     * @param  buffer    the data received with the command
     * @return           {@code true} if a current service is set, {@code false} if no current service exists
     * @throws Exception when the current service fails
     */
    public boolean process(int cmd, Buffer buffer) throws Exception {
        Service current = getService();
        if (current != null) {
            current.process(cmd, buffer);
            return true;
        }
        return false;
    }
}
