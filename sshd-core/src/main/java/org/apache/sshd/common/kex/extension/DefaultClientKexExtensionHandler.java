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
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.apache.sshd.common.AttributeRepository.AttributeKey;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.extension.parser.ServerSignatureAlgorithms;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
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
     * Session {@link AttributeKey} used to store whether the extension indicator was already sent.
     */
    public static final AttributeKey<Boolean> CLIENT_PROPOSAL_MADE = new AttributeKey<>();

    public DefaultClientKexExtensionHandler() {
        super();
    }

    @Override
    public boolean isKexExtensionsAvailable(Session session, AvailabilityPhase phase) throws IOException {
        return !AvailabilityPhase.PREKEX.equals(phase);
    }

    @Override
    public void handleKexInitProposal(
            Session session, boolean initiator, Map<KexProposalOption, String> proposal)
            throws IOException {
        // If it's the very first time, we may add the marker telling the server that we are ready to
        // handle SSH_MSG_EXT_INFO.
        if (session == null || session.isServerSession() || !initiator) {
            return;
        }
        if (session.getAttribute(CLIENT_PROPOSAL_MADE) != null) {
            return;
        }
        String kexAlgorithms = proposal.get(KexProposalOption.SERVERKEYS);
        if (GenericUtils.isEmpty(kexAlgorithms)) {
            return;
        }
        List<String> algorithms = new ArrayList<>();
        // We're a client. We mustn't send the server extension, and we should send the client extension only once.
        for (String algo : kexAlgorithms.split(",")) { //$NON-NLS-1$
            if (KexExtensions.CLIENT_KEX_EXTENSION.equalsIgnoreCase(algo)
                    || KexExtensions.SERVER_KEX_EXTENSION.equalsIgnoreCase(algo)) {
                continue;
            }
            algorithms.add(algo);
        }
        // Tell the server that we want to receive SSH_MSG_EXT_INFO
        algorithms.add(KexExtensions.CLIENT_KEX_EXTENSION);
        if (log.isDebugEnabled()) {
            log.debug("handleKexInitProposal({}): proposing HostKeyAlgorithms {}", //$NON-NLS-1$
                    session, algorithms);
        }
        proposal.put(KexProposalOption.SERVERKEYS, String.join(",", algorithms)); //$NON-NLS-1$
        session.setAttribute(CLIENT_PROPOSAL_MADE, Boolean.TRUE);
    }

    @Override
    public boolean handleKexExtensionRequest(
            Session session, int index, int count, String name, byte[] data)
            throws IOException {
        if (ServerSignatureAlgorithms.NAME.equals(name)) {
            handleServerSignatureAlgorithms(session, ServerSignatureAlgorithms.INSTANCE.parseExtension(data));
        }
        return true;
    }

    /**
     * Perform updates after a server-sig-algs extension has been received.
     *
     * @param session
     *            the message was received for
     * @param serverAlgorithms
     *            signature algorithm names announced by the server
     */
    protected void handleServerSignatureAlgorithms(Session session, Collection<String> serverAlgorithms) {
        if (log.isDebugEnabled()) {
            log.debug("handleServerSignatureAlgorithms({}): {}", session, //$NON-NLS-1$
                    serverAlgorithms);
        }
        // Client determines order; server says what it supports. Re-order such that supported ones are
        // at the front, in client order, followed by unsupported ones, also in client order.
        if (serverAlgorithms != null && !serverAlgorithms.isEmpty()) {
            List<NamedFactory<Signature>> clientAlgorithms = session.getSignatureFactories();
            if (log.isDebugEnabled()) {
                log.debug("handleServerSignatureAlgorithms({}): PubkeyAcceptedAlgorithms before: {}", //$NON-NLS-1$
                        session, clientAlgorithms);
            }
            List<NamedFactory<Signature>> unknown = new ArrayList<>();
            Set<String> known = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
            known.addAll(serverAlgorithms);
            for (Iterator<NamedFactory<Signature>> i = clientAlgorithms.iterator(); i.hasNext(); ) {
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
            session.setSignatureFactories(clientAlgorithms);
        }
    }
}
