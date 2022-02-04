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

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.BiConsumer;

import org.apache.sshd.common.AttributeRepository.AttributeKey;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.extension.parser.ServerSignatureAlgorithms;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * A basic default implementation of a server-side {@link KexExtensionHandler} handling the
 * {@link ServerSignatureAlgorithms} KEX extension.
 *
 * @see <a href="https://tools.ietf.org/html/rfc8308">RFC 8308</a>
 */
public class DefaultServerKexExtensionHandler extends AbstractLoggingBean implements KexExtensionHandler {

    /** Default singleton instance. */
    public static final DefaultServerKexExtensionHandler INSTANCE = new DefaultServerKexExtensionHandler();

    /**
     * Session {@link AttributeKey} storing whether the client requested to get the EXT_INFO message. Possible values
     * are:
     * <dl>
     * <dt>{@code null}</dt>
     * <dd>Unknown. We have not yet received the client's KEX proposal. Do not send the message.</dd>
     * <dt>{@code Boolean.TRUE}</dt>
     * <dd>We have received the client's KEX proposal, and the client has requested to get the EXT_INFO message.</dd>
     * <dt>{@code Boolean.FALSE}</dt>
     * <dd>We have received the client's KEX proposal, and the client did not request to get the EXT_INFO message. Do
     * not send the message.</dd>
     * </dl>
     */
    public static final AttributeKey<Boolean> CLIENT_REQUESTED_EXT_INFO = new AttributeKey<>();

    /**
     * Session {@link AttributeKey} storing whether the server sent an EXT_INFO message at {@link KexPhase#NEWKEYS}. A
     * server is supposed to send the message at that point only on the very first NEWKEYS message. Possible values are:
     * <dl>
     * <dt>{@code null} or {@code Boolean.FALSE}</dt>
     * <dd>The EXT_INFO message at {@link KexPhase#NEWKEYS} was not done yet.</dd>
     * <dt>{@code Boolean.TRUE}</dt>
     * <dd>The EXT_INFO message at {@link KexPhase#NEWKEYS} was done.</dd>
     * </dl>
     */
    @SuppressWarnings("javadoc")
    public static final AttributeKey<Boolean> EXT_INFO_SENT_AT_NEWKEYS = new AttributeKey<>();

    public DefaultServerKexExtensionHandler() {
        super();
    }

    @Override
    public void handleKexInitProposal(Session session, boolean initiator, Map<KexProposalOption, String> proposal)
            throws Exception {
        if (!initiator) {
            if (session.getAttribute(CLIENT_REQUESTED_EXT_INFO) == null) {
                // Only the first time, not on re-KEX
                String algorithms = proposal.get(KexProposalOption.ALGORITHMS);
                boolean clientWantsExtInfo = Arrays.asList(GenericUtils.split(algorithms, ','))
                        .contains(KexExtensions.CLIENT_KEX_EXTENSION);
                session.setAttribute(CLIENT_REQUESTED_EXT_INFO, clientWantsExtInfo);
                if (clientWantsExtInfo && log.isTraceEnabled()) {
                    log.trace("handleKexInitProposal({}): got ext-info-c from client", session);
                }
            }
        }
    }

    @Override
    public void sendKexExtensions(Session session, KexPhase phase) throws Exception {
        if (phase == KexPhase.NEWKEYS) {
            Boolean alreadySent = session.getAttribute(EXT_INFO_SENT_AT_NEWKEYS);
            if ((alreadySent != null) && alreadySent.booleanValue()) {
                // It's not the first NEWKEYS.
                return;
            }
            session.setAttribute(EXT_INFO_SENT_AT_NEWKEYS, Boolean.TRUE);
        }
        Boolean doExtInfo = session.getAttribute(CLIENT_REQUESTED_EXT_INFO);
        if ((doExtInfo == null) || !doExtInfo.booleanValue()) {
            if (log.isTraceEnabled()) {
                log.trace("sendKexExtensions({})[{}]: client did not send ext-info-c; skipping sending SSH_MSG_EXT_INFO",
                        session, phase);
            }
            return;
        }
        Map<String, Object> extensions = new LinkedHashMap<>();
        collectExtensions(session, phase, extensions::put);
        if (!extensions.isEmpty()) {
            Buffer buffer = session.createBuffer(KexExtensions.SSH_MSG_EXT_INFO);
            KexExtensions.putExtensions(extensions.entrySet(), buffer);
            if (log.isDebugEnabled()) {
                log.debug("sendKexExtensions({})[{}]: sending SSH_MSG_EXT_INFO with {} info records", session, phase,
                        extensions.size());
            }
            // We must send the SSH_MSG_EXT_INFO as the next packet following our SSH_MSG_NEWKEYS message, which we just
            // sent. RFC 8308 recommends that "the server sends its SSH_MSG_EXT_INFO not only as the next packet after
            // SSH_MSG_NEWKEYS, but without delay". Note that the message will never be queued since it has low command
            // ID; SSH_MSG_EXT_INFO is 7.
            session.writePacket(buffer);
        } else if (log.isDebugEnabled()) {
            log.debug("sendKexExtensions({})[{}]: no extension info; skipping sending SSH_MSG_EXT_INFO", session, phase);
        }
    }

    /**
     * Collects extension info records, handing them off to the given {@code marshaller} for writing into an
     * {@link KexExtensions#SSH_MSG_EXT_INFO} message.
     * <p>
     * This default implementation marshals a {@link ServerSignatureAlgorithms} extension if the {@code phase} is
     * {@link KexPhase#NEWKEYS}.
     * </p>
     *
     * @param session    {@link Session} to send the KEX extension information for
     * @param phase      {@link KexPhase} of the SSH protocol
     * @param marshaller {@link BiConsumer} writing the extensions into an SSH message
     */
    @SuppressWarnings("javadoc")
    public void collectExtensions(Session session, KexPhase phase, BiConsumer<String, Object> marshaller) {
        if (phase == KexPhase.NEWKEYS) {
            Collection<String> algorithms = session.getSignatureFactoriesNames();
            if (!GenericUtils.isEmpty(algorithms)) {
                marshaller.accept(ServerSignatureAlgorithms.NAME, algorithms);
                if (log.isDebugEnabled()) {
                    log.debug("collectExtensions({})[{}]: extension info {}: {}", session, phase,
                            ServerSignatureAlgorithms.NAME, String.join(",", algorithms));
                }
            } else if (log.isWarnEnabled()) {
                log.warn("collectExtensions({})[{}]: extension info {} has no algorithms; skipping", session, phase,
                        ServerSignatureAlgorithms.NAME);
            }
        }
    }
}
