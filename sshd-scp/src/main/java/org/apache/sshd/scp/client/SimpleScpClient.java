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

package org.apache.sshd.scp.client;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.Channel;
import java.security.KeyPair;
import java.util.Objects;

import org.apache.sshd.client.simple.SimpleClientConfigurator;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * A simplified <U>synchronous</U> API for obtaining SCP sessions.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SimpleScpClient extends Channel {
    /**
     * Creates an SCP session on the default port and logs in using the provided credentials
     *
     * @param  host        The target host name or address
     * @param  username    Username
     * @param  password    Password
     * @return             Created {@link CloseableScpClient} - <B>Note:</B> closing the client also closes its
     *                     underlying session
     * @throws IOException If failed to login or authenticate
     */
    default CloseableScpClient scpLogin(String host, String username, String password) throws IOException {
        return scpLogin(host, SimpleClientConfigurator.DEFAULT_PORT, username, password);
    }

    /**
     * Creates an SCP session using the provided credentials
     *
     * @param  host        The target host name or address
     * @param  port        The target port
     * @param  username    Username
     * @param  password    Password
     * @return             Created {@link CloseableScpClient} - <B>Note:</B> closing the client also closes its
     *                     underlying session
     * @throws IOException If failed to login or authenticate
     */
    default CloseableScpClient scpLogin(String host, int port, String username, String password) throws IOException {
        return scpLogin(InetAddress.getByName(ValidateUtils.checkNotNullAndNotEmpty(host, "No host")), port, username,
                password);
    }

    /**
     * Creates an SCP session on the default port and logs in using the provided credentials
     *
     * @param  host        The target host name or address
     * @param  username    Username
     * @param  identity    The {@link KeyPair} identity
     * @return             Created {@link CloseableScpClient} - <B>Note:</B> closing the client also closes its
     *                     underlying session
     * @throws IOException If failed to login or authenticate
     */
    default CloseableScpClient scpLogin(String host, String username, KeyPair identity) throws IOException {
        return scpLogin(host, SimpleClientConfigurator.DEFAULT_PORT, username, identity);
    }

    /**
     * Creates an SCP session using the provided credentials
     *
     * @param  host        The target host name or address
     * @param  port        The target port
     * @param  username    Username
     * @param  identity    The {@link KeyPair} identity
     * @return             Created {@link CloseableScpClient} - <B>Note:</B> closing the client also closes its
     *                     underlying session
     * @throws IOException If failed to login or authenticate
     */
    default CloseableScpClient scpLogin(String host, int port, String username, KeyPair identity) throws IOException {
        return scpLogin(InetAddress.getByName(ValidateUtils.checkNotNullAndNotEmpty(host, "No host")), port, username,
                identity);
    }

    /**
     * Creates an SCP session on the default port and logs in using the provided credentials
     *
     * @param  host        The target host {@link InetAddress}
     * @param  username    Username
     * @param  password    Password
     * @return             Created {@link CloseableScpClient} - <B>Note:</B> closing the client also closes its
     *                     underlying session
     * @throws IOException If failed to login or authenticate
     */
    default CloseableScpClient scpLogin(InetAddress host, String username, String password) throws IOException {
        return scpLogin(host, SimpleClientConfigurator.DEFAULT_PORT, username, password);
    }

    /**
     * Creates an SCP session using the provided credentials
     *
     * @param  host        The target host {@link InetAddress}
     * @param  port        The target port
     * @param  username    Username
     * @param  password    Password
     * @return             Created {@link CloseableScpClient} - <B>Note:</B> closing the client also closes its
     *                     underlying session
     * @throws IOException If failed to login or authenticate
     */
    default CloseableScpClient scpLogin(InetAddress host, int port, String username, String password) throws IOException {
        return scpLogin(new InetSocketAddress(Objects.requireNonNull(host, "No host address"), port), username, password);
    }

    /**
     * Creates an SCP session on the default port and logs in using the provided credentials
     *
     * @param  host        The target host {@link InetAddress}
     * @param  username    Username
     * @param  identity    The {@link KeyPair} identity
     * @return             Created {@link CloseableScpClient} - <B>Note:</B> closing the client also closes its
     *                     underlying session
     * @throws IOException If failed to login or authenticate
     */
    default CloseableScpClient scpLogin(InetAddress host, String username, KeyPair identity) throws IOException {
        return scpLogin(host, SimpleClientConfigurator.DEFAULT_PORT, username, identity);
    }

    /**
     * Creates an SCP session using the provided credentials
     *
     * @param  host        The target host {@link InetAddress}
     * @param  port        The target port
     * @param  username    Username
     * @param  identity    The {@link KeyPair} identity
     * @return             Created {@link CloseableScpClient} - <B>Note:</B> closing the client also closes its
     *                     underlying session
     * @throws IOException If failed to login or authenticate
     */
    default CloseableScpClient scpLogin(InetAddress host, int port, String username, KeyPair identity) throws IOException {
        return scpLogin(new InetSocketAddress(Objects.requireNonNull(host, "No host address"), port), username, identity);
    }

    /**
     * Creates an SCP session using the provided credentials
     *
     * @param  target      The target {@link SocketAddress}
     * @param  username    Username
     * @param  password    Password
     * @return             Created {@link CloseableScpClient} - <B>Note:</B> closing the client also closes its
     *                     underlying session
     * @throws IOException If failed to login or authenticate
     */
    CloseableScpClient scpLogin(SocketAddress target, String username, String password) throws IOException;

    /**
     * Creates an SCP session using the provided credentials
     *
     * @param  target      The target {@link SocketAddress}
     * @param  username    Username
     * @param  identity    The {@link KeyPair} identity
     * @return             Created {@link CloseableScpClient} - <B>Note:</B> closing the client also closes its
     *                     underlying session
     * @throws IOException If failed to login or authenticate
     */
    CloseableScpClient scpLogin(SocketAddress target, String username, KeyPair identity) throws IOException;
}
