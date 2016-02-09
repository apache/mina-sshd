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
package org.apache.sshd.server.x11;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface X11ForwardSupport extends Closeable, IoHandler {
    /**
     * Configuration value on the {@link FactoryManager} to control the
     * channel open timeout. If not specified then {@link #DEFAULT_CHANNEL_OPEN_TIMEOUT}
     * value is used
     */
    String CHANNEL_OPEN_TIMEOUT_PROP = "x11-fwd-open-timeout";
    long DEFAULT_CHANNEL_OPEN_TIMEOUT = TimeUnit.SECONDS.toMillis(30L);

    /**
     * Configuration value to control from which X11 display number to start
     * looking for a free value. If not specified, then {@link #DEFAULT_X11_DISPLAY_OFFSET}
     * is used
     */
    String X11_DISPLAY_OFFSET = "x11-fwd-display-offset";
    int DEFAULT_X11_DISPLAY_OFFSET = 10;

    /**
     * Configuration value to control up to which (but not including) X11 display number
     * to look or a free value. If not specified, then {@link #DEFAULT_X11_MAX_DISPLAYS}
     * is used
     */
    String X11_MAX_DISPLAYS = "x11-fwd-max-display";
    int DEFAULT_X11_MAX_DISPLAYS = 1000;

    /**
     * Configuration value to control the base port number for the X11 display
     * number socket binding. If not specified then {@link #DEFAULT_X11_BASE_PORT}
     * value is used
     */
    String X11_BASE_PORT = "x11-fwd-base-port";
    int DEFAULT_X11_BASE_PORT = 6000;

    /**
     * Configuration value to control the host used to bind to for the X11 display
     * when looking for a free port. If not specified, then {@link #DEFAULT_X11_BIND_HOST}
     * is used
     */
    String X11_BIND_HOST = "x11-fwd-bind-host";
    String DEFAULT_X11_BIND_HOST = SshdSocketAddress.LOCALHOST_IP;

    /**
     * Key for the user DISPLAY variable
     */
    String ENV_DISPLAY = "DISPLAY";

    /**
     * &quot;xauth&quot; command name
     */
    String XAUTH_COMMAND = System.getProperty("sshd.XAUTH_COMMAND", "xauth");

    String createDisplay(
            boolean singleConnection, String authenticationProtocol, String authenticationCookie, int screen)
                    throws IOException;
}
