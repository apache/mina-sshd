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
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.stream.Stream;

import org.apache.sshd.common.AttributeRepository.AttributeKey;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.extension.parser.ServerSignatureAlgorithms;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * Detects if the server sends a
 * <A HREF="https://tools.ietf.org/html/rfc8308#section-3.1">&quot;server-sig-algs&quot;</A> and updates the client
 * session by adding the <A HREF="https://tools.ietf.org/html/rfc8332">&quot;rsa-sha2-256/512&quot;</A> signature
 * factories (if not already added).
 *
 * <B>Note:</B> experimental - used for development purposes and as an example
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultClientKexExtensionHandler extends AbstractLoggingBean implements KexExtensionHandler {
    /**
     * Session {@link AttributeKey} used to store the client's proposal
     */
    public static final AttributeKey<Map<KexProposalOption, String>> CLIENT_PROPOSAL_KEY = new AttributeKey<>();

    /**
     * Session {@link AttributeKey} used to store the server's proposal
     */
    public static final AttributeKey<Map<KexProposalOption, String>> SERVER_PROPOSAL_KEY = new AttributeKey<>();

    public static final NavigableSet<String> DEFAULT_EXTRA_SIGNATURES = Collections.unmodifiableNavigableSet(
            GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER,
                    KeyUtils.RSA_SHA256_KEY_TYPE_ALIAS,
                    KeyUtils.RSA_SHA512_KEY_TYPE_ALIAS));

    public static final DefaultClientKexExtensionHandler INSTANCE = new DefaultClientKexExtensionHandler();

    public DefaultClientKexExtensionHandler() {
        super();
    }

    @Override
    public boolean isKexExtensionsAvailable(Session session, AvailabilityPhase phase) throws IOException {
        if ((session == null) || session.isServerSession()) {
            return false;
        }

        // We only need to take special care during the proposal build phase
        if (phase != AvailabilityPhase.PROPOSAL) {
            return true;
        }

        boolean debugEnabled = log.isDebugEnabled();
        // Check if client already sent its proposal - if not, we can still influence it
        Map<KexProposalOption, String> clientProposal = session.getAttribute(CLIENT_PROPOSAL_KEY);
        Map<KexProposalOption, String> serverProposal = session.getAttribute(SERVER_PROPOSAL_KEY);
        if (GenericUtils.isNotEmpty(clientProposal)) {
            if (debugEnabled) {
                log.debug("isKexExtensionsAvailable({})[{}] already sent proposal={} (server={})",
                        session, phase, clientProposal, serverProposal);
            }
            return false;
        }

        /*
         * According to https://tools.ietf.org/html/rfc8308#section-3.1:
         *
         *
         * Note that implementations are known to exist that apply authentication penalties if the client attempts to
         * use an unexpected public key algorithm.
         *
         * Therefore we want to be sure the server declared its support for extensions before we declare ours.
         */
        if (GenericUtils.isEmpty(serverProposal)) {
            if (debugEnabled) {
                log.debug("isKexExtensionsAvailable({})[{}] no server proposal", session, phase);
            }
            return false;
        }

        String algos = serverProposal.get(KexProposalOption.ALGORITHMS);
        String extDeclared = Stream.of(GenericUtils.split(algos, ','))
                .filter(s -> KexExtensions.SERVER_KEX_EXTENSION.equalsIgnoreCase(s))
                .findFirst()
                .orElse(null);
        if (GenericUtils.isEmpty(extDeclared)) {
            if (debugEnabled) {
                log.debug("isKexExtensionsAvailable({})[{}] server proposal does not include extension indicator: {}",
                        session, phase, algos);
            }
            return false;
        }

        return true;
    }

    @Override
    public void handleKexInitProposal(
            Session session, boolean initiator, Map<KexProposalOption, String> proposal)
            throws IOException {
        if (session.isServerSession()) {
            return; // just in case
        }

        session.setAttribute(initiator ? CLIENT_PROPOSAL_KEY : SERVER_PROPOSAL_KEY, new EnumMap<>(proposal));
        if (log.isDebugEnabled()) {
            log.debug("handleKexInitProposal({})[initiator={}] proposal={}", session, initiator, proposal);
        }
        return;
    }

    @Override
    public boolean handleKexExtensionRequest(
            Session session, int index, int count, String name, byte[] data)
            throws IOException {
        if (!ServerSignatureAlgorithms.NAME.equalsIgnoreCase(name)) {
            return true; // process next extension (if available)
        }

        Collection<String> sigAlgos = ServerSignatureAlgorithms.INSTANCE.parseExtension(data);
        updateAvailableSignatureFactories(session, sigAlgos);
        return false; // don't care about any more extensions (for now)
    }

    public List<NamedFactory<Signature>> updateAvailableSignatureFactories(
            Session session, Collection<String> extraAlgos)
            throws IOException {
        List<NamedFactory<Signature>> available = session.getSignatureFactories();
        List<NamedFactory<Signature>> updated = resolveUpdatedSignatureFactories(session, available, extraAlgos);
        if (!GenericUtils.isSameReference(available, updated)) {
            if (log.isDebugEnabled()) {
                log.debug("updateAvailableSignatureFactories({}) available={}, updated={}",
                        session, available, updated);
            }
            session.setSignatureFactories(updated);
        }

        return updated;
    }

    /**
     * Checks if the extra signature algorithms are already included in the available ones, and adds the extra ones (if
     * supported).
     *
     * @param  session     The {@link Session} for which the resolution occurs
     * @param  available   The available signature factories
     * @param  extraAlgos  The extra requested signatures - ignored if {@code null}/empty
     * @return             The resolved signature factories - same as input if nothing added
     * @throws IOException If failed to resolve the factories
     */
    public List<NamedFactory<Signature>> resolveUpdatedSignatureFactories(
            Session session, List<NamedFactory<Signature>> available, Collection<String> extraAlgos)
            throws IOException {
        boolean debugEnabled = log.isDebugEnabled();
        List<NamedFactory<Signature>> toAdd = resolveRequestedSignatureFactories(session, extraAlgos);
        if (GenericUtils.isEmpty(toAdd)) {
            if (debugEnabled) {
                log.debug("resolveUpdatedSignatureFactories({}) Nothing to add to {} out of {}",
                        session, NamedResource.getNames(available), extraAlgos);
            }
            return available;
        }

        for (int index = 0; index < toAdd.size(); index++) {
            NamedFactory<Signature> f = toAdd.get(index);
            String name = f.getName();
            NamedFactory<Signature> a = available.stream()
                    .filter(s -> Objects.equals(name, s.getName()))
                    .findFirst()
                    .orElse(null);
            if (a == null) {
                continue;
            }

            if (debugEnabled) {
                log.debug("resolveUpdatedSignatureFactories({}) skip {} - already available", session, name);
            }

            toAdd.remove(index);
            index--; // compensate for loop auto-increment
        }

        return updateAvailableSignatureFactories(session, available, toAdd);
    }

    public List<NamedFactory<Signature>> updateAvailableSignatureFactories(
            Session session, List<NamedFactory<Signature>> available, Collection<? extends NamedFactory<Signature>> toAdd)
            throws IOException {
        boolean debugEnabled = log.isDebugEnabled();
        if (GenericUtils.isEmpty(toAdd)) {
            if (debugEnabled) {
                log.debug("updateAvailableSignatureFactories({}) nothing to add to {}",
                        session, NamedResource.getNames(available));
            }
            return available;
        }

        List<NamedFactory<Signature>> updated = new ArrayList<>(available.size() + toAdd.size());
        updated.addAll(available);

        for (NamedFactory<Signature> f : toAdd) {
            int index = resolvePreferredSignaturePosition(session, updated, f);
            if (debugEnabled) {
                log.debug("updateAvailableSignatureFactories({}) add {} at position={}", session, f, index);
            }
            if ((index < 0) || (index >= updated.size())) {
                updated.add(f);
            } else {
                updated.add(index, f);
            }
        }

        return updated;
    }

    public int resolvePreferredSignaturePosition(
            Session session, List<? extends NamedFactory<Signature>> factories, NamedFactory<Signature> factory)
            throws IOException {
        return SignatureFactory.resolvePreferredSignaturePosition(factories, factory);
    }

    public List<NamedFactory<Signature>> resolveRequestedSignatureFactories(
            Session session, Collection<String> extraAlgos)
            throws IOException {
        if (GenericUtils.isEmpty(extraAlgos)) {
            return Collections.emptyList();
        }

        List<NamedFactory<Signature>> toAdd = Collections.emptyList();
        boolean debugEnabled = log.isDebugEnabled();
        for (String algo : extraAlgos) {
            NamedFactory<Signature> factory = resolveRequestedSignatureFactory(session, algo);
            if (factory == null) {
                if (debugEnabled) {
                    log.debug("resolveRequestedSignatureFactories({}) skip {} - no factory found", session, algo);
                }
                continue;
            }

            if ((factory instanceof OptionalFeature) && (!((OptionalFeature) factory).isSupported())) {
                if (debugEnabled) {
                    log.debug("resolveRequestedSignatureFactories({}) skip {} - not supported", session, algo);
                }
                continue;
            }

            if (toAdd.isEmpty()) {
                toAdd = new ArrayList<>(extraAlgos.size());
            }
            toAdd.add(factory);
        }

        return toAdd;
    }

    public NamedFactory<Signature> resolveRequestedSignatureFactory(Session session, String name) throws IOException {
        return BuiltinSignatures.fromFactoryName(name);
    }
}
