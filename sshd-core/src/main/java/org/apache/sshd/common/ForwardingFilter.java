/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.common.util.AbstractLoggingBean;
import org.apache.sshd.common.util.GenericUtils;

/**
 * Determines if a forwarding request will be permitted.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ForwardingFilter {
    /**
     * Determine if the session may arrange for agent forwarding.
     * <p>
     * This server process will open a new listen socket locally and export
     * the address in the {@link SshAgent#SSH_AUTHSOCKET_ENV_NAME} environment
     * variable.
     *
     * @param session session requesting permission to forward the agent.
     * @return true if the agent forwarding is permitted, false if denied.
     */
    boolean canForwardAgent(Session session);

    /**
     * Determine if the session may arrange for X11 forwarding.
     * <p>
     * This server process will open a new listen socket locally and export
     * the address in the environment so X11 clients can be tunneled to the
     * user's X11 display server.
     *
     * @param session session requesting permission to forward X11 connections.
     * @return true if the X11 forwarding is permitted, false if denied.
     */
    boolean canForwardX11(Session session);

    /**
     * Determine if the session may listen for inbound connections.
     * <p>
     * This server process will open a new listen socket on the address given
     * by the client (usually 127.0.0.1 but may be any address).  Any inbound
     * connections to this socket will be tunneled over the session to the
     * client, which the client will then forward the connection to another
     * host on the client's side of the network.
     *
     * @param address address the client has requested this server listen
     *  for inbound connections on, and relay them through the client.
     * @param session session requesting permission to listen for connections.
     * @return true if the socket is permitted; false if it must be denied.
     */
    boolean canListen(SshdSocketAddress address, Session session);

    /**
     * The type of requested connection forwarding. The type's {@link #getName()}
     * method returns the SSH request type
     */
    enum Type implements NamedResource { 
        Direct("direct-tcpip"),
        Forwarded("forwarded-tcpip");
        
        private final String name;

        @Override
        public final String getName() {
            return name;
        }

        Type(String name) {
            this.name = name;
        }
        
        public static final Set<Type> VALUES = 
                Collections.unmodifiableSet(EnumSet.allOf(Type.class));

        /**
         * @param name Either the enum name or the request - ignored if {@code null}/empty
         * @return The matching {@link Type} value - case <U>insensitive</U>,
         * or {@code null} if no match found
         * @see #fromName(String)
         * @see #fromEnumName(String)
         */
        public static final Type fromString(String name) {
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
         * @param name The request name - ignored if {@code null}/empty
         * @return The matching {@link Type} value - case <U>insensitive</U>,
         * or {@code null} if no match found
         */
        public static final Type fromName(String name) {
            if (GenericUtils.isEmpty(name)) {
                return null;
            }
            
            for (Type t : VALUES) {
                if (name.equalsIgnoreCase(t.getName())) {
                    return t;
                }
            }
            
            return null;
        }
        
        /**
         * @param name The enum value name - ignored if {@code null}/empty
         * @return The matching {@link Type} value - case <U>insensitive</U>,
         * or {@code null} if no match found
         */
        public static final Type fromEnumName(String name) {
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
     * Determine if the session may create an outbound connection.
     * <p>
     * This server process will connect to another server listening on the
     * address specified by the client.  Usually this is to another port on
     * the same host (127.0.0.1) but may be to any other system this server
     * can reach on the server's side of the network.
     *
     * @param type The {@link Type} of requested connection forwarding
     * @param address address the client has requested this server listen
     *  for inbound connections on, and relay them through the client.
     * @param session session requesting permission to listen for connections.
     * @return true if the socket is permitted; false if it must be denied.
     */
    boolean canConnect(Type type, SshdSocketAddress address, Session session);
    
    /**
     * A {@link ForwardingFilter} implementation that returns the same &quot;static&quot;
     * result for <U>all</U> the queries.
     */
    public static class StaticDecisionForwardingFilter extends AbstractLoggingBean implements ForwardingFilter {
        private final boolean acceptance;

        /**
         * @param acceptance The acceptance status for <U>all</U> the queries
         */
        public StaticDecisionForwardingFilter(boolean acceptance) {
            this.acceptance = acceptance;
        }
        
        public final boolean isAccepted() {
            return acceptance;
        }

        @Override
        public boolean canForwardAgent(Session session) {
            return checkAcceptance("auth-agent-req@openssh.com", session, SshdSocketAddress.LOCALHOST_ADDRESS);
        }

        @Override
        public boolean canForwardX11(Session session) {
            return checkAcceptance("x11-req", session, SshdSocketAddress.LOCALHOST_ADDRESS);
        }

        @Override
        public boolean canListen(SshdSocketAddress address, Session session) {
            return checkAcceptance("tcpip-forward", session, address);
        }

        @Override
        public boolean canConnect(Type type, SshdSocketAddress address, Session session) {
            return checkAcceptance(type.getName(), session, address);
        }
        
        /**
         * @param request The SSH request that ultimately led to this filter being consulted
         * @param session The requesting {@link Session}
         * @param target The request target - may be {@link SshdSocketAddress#LOCALHOST_ADDRESS}
         * if no real target
         * @return The (static) {@link #isAccepted()} flag
         */
        protected boolean checkAcceptance(String request, Session session, SshdSocketAddress target) {
            boolean accepted = isAccepted();
            if (log.isDebugEnabled()) {
                log.debug("checkAcceptance(" + request + ")[" + session + "] acceptance for target=" + target + " is " + accepted);
            }
            return accepted;
        }
    }
    
    /**
     * A {@link ForwardingFilter} that accepts all requests
     */
    public static class AcceptAllForwardingFilter extends StaticDecisionForwardingFilter {
        public static final AcceptAllForwardingFilter INSTANCE = new AcceptAllForwardingFilter();

        public AcceptAllForwardingFilter() {
            super(true);
        }
    }

    /**
     * A {@link ForwardingFilter} that rejects all requests
     */
    public static class RejectAllForwardingFilter extends StaticDecisionForwardingFilter {
        public static final RejectAllForwardingFilter INSTANCE = new RejectAllForwardingFilter();

        public RejectAllForwardingFilter() {
            super(false);
        }
    }
}
