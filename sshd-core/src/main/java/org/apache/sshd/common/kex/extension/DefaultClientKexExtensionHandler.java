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

package org.apache.sshd.common.kex.extension;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.apache.sshd.common.AttributeRepository.AttributeKey;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.kex.extension.parser.HostBoundPubkeyAuthentication;
import org.apache.sshd.common.kex.extension.parser.ServerSignatureAlgorithms;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * Detects if the server sends a
 * <A HREF="https://tools.ietf.org/html/rfc8308#section-3.1">&quot;server-sig-algs&quot;</A> and updates the client
 * session by adding the <A HREF="https://tools.ietf.org/html/rfc8332">&quot;rsa-sha2-256/512&quot;</A> signature
 * factories (if not already added).
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultClientKexExtensionHandler extends AbstractLoggingBean implements KexExtensionHandler {

    /** Default singleton instance. */
    public static final DefaultClientKexExtensionHandler INSTANCE = new DefaultClientKexExtensionHandler();

    /**
     * Session {@link AttributeKey} storing the algorithms announced by the server as known.
     */
    public static final AttributeKey<Set<String>> SERVER_ALGORITHMS = new AttributeKey<>();

    /**
     * Session {@link AttributeKey} storing the version if the server supports host-bound public key authentication.
     */
    public static final AttributeKey<Integer> HOSTBOUND_AUTHENTICATION = new AttributeKey<>();

    public DefaultClientKexExtensionHandler() {
        super();
    }

    @Override
    public boolean isKexExtensionsAvailable(Session session, AvailabilityPhase phase) throws IOException {
        return !AvailabilityPhase.PREKEX.equals(phase);
    }

    @Override
    public boolean handleKexExtensionRequest(
            Session session, int index, int count, String name, byte[] data)
            throws IOException {
        if (ServerSignatureAlgorithms.NAME.equals(name)) {
            handleServerSignatureAlgorithms(session, ServerSignatureAlgorithms.INSTANCE.parseExtension(data));
        } else if (HostBoundPubkeyAuthentication.NAME.equals(name)) {
            Integer version = HostBoundPubkeyAuthentication.INSTANCE.parseExtension(data);
            if (version == null) {
                if (log.isDebugEnabled()) {
                    log.debug("handleKexExtensionRequest({}) : ignoring unknown {} extension", session,
                            HostBoundPubkeyAuthentication.NAME);
                }
            } else if (version.intValue() != 0) {
                if (log.isDebugEnabled()) {
                    log.debug("handleKexExtensionRequest({}) : ignoring unknown {} version {}", session,
                            HostBoundPubkeyAuthentication.NAME, version);
                }
            } else {
                session.setAttribute(HOSTBOUND_AUTHENTICATION, version);
            }
        }
        return true;
    }

    /**
     * Perform updates after a server-sig-algs extension has been received. The set of algorithms announced by the
     * server is set as attribute {@link #SERVER_ALGORITHMS} of the {@code session}.
     *
     * @param session          the message was received for
     * @param serverAlgorithms signature algorithm names announced by the server
     */
    protected void handleServerSignatureAlgorithms(Session session, Collection<String> serverAlgorithms) {
        if (log.isDebugEnabled()) {
            log.debug("handleServerSignatureAlgorithms({}): {}", session, //$NON-NLS-1$
                    serverAlgorithms);
        }
        // Client determines order; server says what it supports. Re-order such that supported ones are
        // at the front, in client order, followed by unsupported ones, also in client order.
        if (serverAlgorithms != null && !serverAlgorithms.isEmpty()) {
            List<NamedFactory<Signature>> clientAlgorithms = new ArrayList<>(session.getSignatureFactories());
            if (log.isDebugEnabled()) {
                log.debug("handleServerSignatureAlgorithms({}): PubkeyAcceptedAlgorithms before: {}", //$NON-NLS-1$
                        session, clientAlgorithms);
            }
            List<NamedFactory<Signature>> unknown = new ArrayList<>();
            Set<String> known = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
            known.addAll(serverAlgorithms);
            for (Iterator<NamedFactory<Signature>> i = clientAlgorithms.iterator(); i.hasNext();) {
                NamedFactory<Signature> algo = i.next();
                if (!known.contains(algo.getName())) {
                    unknown.add(algo);
                    i.remove();
                }
            }
            // Re-add the unknown ones at the end. Per RFC 8308, some servers may not announce _all_ their
            // supported algorithms, and a client may use unknown algorithms.
            clientAlgorithms.addAll(unknown);
            if (log.isDebugEnabled()) {
                log.debug("handleServerSignatureAlgorithms({}): PubkeyAcceptedAlgorithms after: {}", //$NON-NLS-1$
                        session, clientAlgorithms);
            }
            session.setAttribute(SERVER_ALGORITHMS, known);
            session.setSignatureFactories(clientAlgorithms);
        }
    }
}
