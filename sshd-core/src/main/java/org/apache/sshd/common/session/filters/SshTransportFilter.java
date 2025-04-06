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
package org.apache.sshd.common.session.filters;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.cipher.CipherInformation;
import org.apache.sshd.common.compression.CompressionInformation;
import org.apache.sshd.common.filter.DefaultFilterChain;
import org.apache.sshd.common.filter.FilterChain;
import org.apache.sshd.common.filter.InputHandler;
import org.apache.sshd.common.filter.IoFilter;
import org.apache.sshd.common.filter.OutputHandler;
import org.apache.sshd.common.future.KeyExchangeFuture;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.mac.MacInformation;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.session.filters.CryptFilter.EncryptionListener;
import org.apache.sshd.common.session.filters.kex.KexFilter;
import org.apache.sshd.common.session.filters.kex.KexFilter.HostKeyChecker;
import org.apache.sshd.common.session.filters.kex.KexFilter.Proposer;
import org.apache.sshd.common.session.filters.kex.KexListener;
import org.apache.sshd.common.session.helpers.AbstractSession;

/**
 * A filter encapsulating the basic SSH transport up to and including KEX.
 */
public class SshTransportFilter extends IoFilter {

    private final FilterChain filters = new DefaultFilterChain();

    private final CryptFilter cryptFilter;
    private final CompressionFilter compressionFilter;
    private final KexFilter kexFilter;

    /**
     * Creates a new SSH transport filter.
     *
     * @param session    {@link AbstractSession} this filter is for
     * @param random     {@link Random} instance to use
     * @param identities {@link SshIdentHandler} for handling the SSH identificaton string
     * @param events     {@link SessionListener} to report some events
     * @param proposer   {@link Proposer} to get KEX proposals
     * @param checker    {@link HostKeyChecker} to check the peer's host key; may be {@code null} if on a server
     */
    public SshTransportFilter(AbstractSession session, Random random, SshIdentHandler identities, SessionListener events,
                              Proposer proposer, HostKeyChecker checker) {
        IdentFilter ident = new IdentFilter();
        ident.setPropertyResolver(session);
        ident.setIdentHandler(identities);
        filters.addLast(ident);

        cryptFilter = new CryptFilter();
        cryptFilter.setSession(session);
        cryptFilter.setRandom(random);
        filters.addLast(cryptFilter);

        compressionFilter = new CompressionFilter();
        compressionFilter.setSession(session);
        filters.addLast(compressionFilter);

        filters.addLast(new PacketLoggingFilter(session, cryptFilter));

        DelayKexInitFilter delayKexFilter = new DelayKexInitFilter();
        delayKexFilter.setSession(session);
        filters.addLast(delayKexFilter);

        filters.addLast(new InjectIgnoreFilter(session, random));

        kexFilter = new KexFilter(session, random, cryptFilter, compressionFilter, events, proposer, checker);
        filters.addLast(kexFilter);

        // Forward the protocol identification to the KexFilter; it's needed for KEX.
        ident.addIdentListener((peer, id) -> {
            if (peer == session.isServerSession()) {
                kexFilter.setClientIdent(id);
            } else {
                kexFilter.setServerIdent(id);
            }
        });

        // Connect the local filter chain to the one containing this SshTransportFilter
        filters.addFirst(new InConnector(this));
        filters.addLast(new OutConnector(this));
    }

    @Override
    public InputHandler in() {
        return filters.getFirst().in();
    }

    @Override
    public OutputHandler out() {
        return filters.getLast().out();
    }

    public KeyExchangeFuture startKex() throws Exception {
        return kexFilter.startKex();
    }

    public void shutdown() {
        kexFilter.shutdown();
    }

    public boolean isStrictKex() {
        return kexFilter.isStrictKex();
    }

    public boolean isInitialKexDone() {
        return kexFilter.isInitialKexDone();
    }

    public AtomicReference<KexState> getKexState() {
        return kexFilter.getKexState();
    }

    public Map<KexProposalOption, String> getNegotiated() {
        return kexFilter.getNegotiated();
    }

    public Map<KexProposalOption, String> getClientProposal() {
        return kexFilter.getClientProposal();
    }

    public Map<KexProposalOption, String> getServerProposal() {
        return kexFilter.getServerProposal();
    }

    public byte[] getSessionId() {
        return kexFilter.getSessionId();
    }

    public void addKexListener(KexListener listener) {
        kexFilter.addKexListener(listener);
    }

    public void removeKexListener(KexListener listener) {
        kexFilter.removeKexListener(listener);
    }

    public void addEncryptionListener(EncryptionListener listener) {
        cryptFilter.addEncryptionListener(listener);
    }

    public void removeEncryptionListener(EncryptionListener listener) {
        cryptFilter.removeEncryptionListener(listener);
    }

    public boolean isSecure() {
        return cryptFilter.isSecure();
    }

    public long getLastInputSequenceNumber() {
        return cryptFilter.getLastInputSequenceNumber();
    }

    public long getInputSequenceNumber() {
        return cryptFilter.getInputSequenceNumber();
    }

    public long getOutputSequenceNumber() {
        return cryptFilter.getOutputSequenceNumber();
    }

    public CipherInformation getCipherInformation(boolean incoming) {
        return incoming ? cryptFilter.getInputSettings().getCipher() : cryptFilter.getOutputSettings().getCipher();
    }

    public MacInformation getMacInformation(boolean incoming) {
        return incoming ? cryptFilter.getInputSettings().getMac() : cryptFilter.getOutputSettings().getMac();
    }

    public void enableInputCompression() {
        compressionFilter.enableInput();
    }

    public void enableOutputCompression() {
        compressionFilter.enableOutput();
    }

    public CompressionInformation getCompressionInformation(boolean incoming) {
        return incoming ? compressionFilter.getInputCompression() : compressionFilter.getOutputCompression();
    }

    private static class InConnector extends IoFilter {

        private final SshTransportFilter transport;

        InConnector(SshTransportFilter transport) {
            this.transport = transport;
        }

        @Override
        public InputHandler in() {
            return owner()::passOn;
        }

        @Override
        public OutputHandler out() {
            return transport.owner()::send;
        }

    }

    private static class OutConnector extends IoFilter {

        private final SshTransportFilter transport;

        OutConnector(SshTransportFilter transport) {
            this.transport = transport;
        }

        @Override
        public InputHandler in() {
            return transport.owner()::passOn;
        }

        @Override
        public OutputHandler out() {
            return owner()::send;
        }

    }
}
