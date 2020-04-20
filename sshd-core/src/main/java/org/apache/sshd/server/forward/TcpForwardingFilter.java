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
package org.apache.sshd.server.forward;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface TcpForwardingFilter {
    // According to http://www.freebsd.org/cgi/man.cgi?query=sshd_config&sektion=5
    TcpForwardingFilter DEFAULT = new TcpForwardingFilter() {
        @Override
        public boolean canListen(SshdSocketAddress address, Session session) {
            return true;
        }

        @Override
        public boolean canConnect(Type type, SshdSocketAddress address, Session session) {
            return true;
        }

        @Override
        public String toString() {
            return TcpForwardingFilter.class.getSimpleName() + "[DEFAULT]";
        }
    };

    /**
     * <p>
     * Determine if the session may listen for inbound connections.
     * </p>
     *
     * <p>
     * This server process will open a new listen socket on the address given by the client (usually 127.0.0.1 but may
     * be any address). Any inbound connections to this socket will be tunneled over the session to the client, which
     * the client will then forward the connection to another host on the client's side of the network.
     * </p>
     *
     * @param  address address the client has requested this server listen for inbound connections on, and relay them
     *                 through the client.
     * @param  session The {@link Session} requesting permission to listen for connections.
     * @return         true if the socket is permitted; false if it must be denied.
     */
    boolean canListen(SshdSocketAddress address, Session session);

    /**
     * The type of requested connection forwarding. The type's {@link #getName()} method returns the SSH request type
     */
    enum Type implements NamedResource {
        Direct("direct-tcpip"),
        Forwarded("forwarded-tcpip");

        public static final Set<Type> VALUES = Collections.unmodifiableSet(EnumSet.allOf(Type.class));

        private final String name;

        Type(String name) {
            this.name = name;
        }

        @Override
        public final String getName() {
            return name;
        }

        /**
         * @param  name Either the enum name or the request - ignored if {@code null}/empty
         * @return      The matching {@link Type} value - case <U>insensitive</U>, or {@code null} if no match found
         * @see         #fromName(String)
         * @see         #fromEnumName(String)
         */
        public static Type fromString(String name) {
            if (GenericUtils.isEmpty(name)) {
                return null;
            }

            Type t = fromName(name);
            if (t == null) {
                t = fromEnumName(name);
            }

            return t;
        }

        /**
         * @param  name The request name - ignored if {@code null}/empty
         * @return      The matching {@link Type} value - case <U>insensitive</U>, or {@code null} if no match found
         */
        public static Type fromName(String name) {
            return NamedResource.findByName(name, String.CASE_INSENSITIVE_ORDER, VALUES);
        }

        /**
         * @param  name The enum value name - ignored if {@code null}/empty
         * @return      The matching {@link Type} value - case <U>insensitive</U>, or {@code null} if no match found
         */
        public static Type fromEnumName(String name) {
            if (GenericUtils.isEmpty(name)) {
                return null;
            }

            for (Type t : VALUES) {
                if (name.equalsIgnoreCase(t.name())) {
                    return t;
                }
            }

            return null;
        }
    }

    /**
     * <p>
     * Determine if the session may create an outbound connection.
     * </p>
     *
     * <p>
     * This server process will connect to another server listening on the address specified by the client. Usually this
     * is to another port on the same host (127.0.0.1) but may be to any other system this server can reach on the
     * server's side of the network.
     * </p>
     *
     * @param  type    The {@link Type} of requested connection forwarding
     * @param  address address the client has requested this server listen for inbound connections on, and relay them
     *                 through the client.
     * @param  session session requesting permission to listen for connections.
     * @return         true if the socket is permitted; false if it must be denied.
     */
    boolean canConnect(Type type, SshdSocketAddress address, Session session);
}
