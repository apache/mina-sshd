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

package org.apache.sshd.common.session;

import java.util.Map;

import org.apache.sshd.common.AttributeStore;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.auth.UsernameHolder;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.CipherInformation;
import org.apache.sshd.common.compression.CompressionInformation;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.mac.MacInformation;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.net.ConnectionEndpointsIndicator;

/**
 * A &quot;succinct&quot; summary of the most important attributes of an SSH session
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SessionContext
        extends ConnectionEndpointsIndicator,
        UsernameHolder,
        SessionHeartbeatController,
        AttributeStore,
        Closeable {
    /**
     * Default prefix expected for the client / server identification string
     *
     * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-4.2">RFC 4253 - section 4.2</A>
     */
    String DEFAULT_SSH_VERSION_PREFIX = "SSH-2.0-";

    /**
     * Backward compatible special prefix
     *
     * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-5">RFC 4253 - section 5</A>
     */
    String FALLBACK_SSH_VERSION_PREFIX = "SSH-1.99-";

    /**
     * Maximum number of characters for any single line sent as part of the initial handshake - according to
     * <A HREF="https://tools.ietf.org/html/rfc4253#section-4.2">RFC 4253 - section 4.2</A>:</BR>
     *
     * <P>
     * <CODE>
     *      The maximum length of the string is 255 characters,
     *      including the Carriage Return and Line Feed.
     * </CODE>
     * </P>
     */
    int MAX_VERSION_LINE_LENGTH = 256;

    /**
     * @return A <U>clone</U> of the established session identifier - {@code null} if not yet established
     */
    byte[] getSessionId();

    /**
     * Quick indication if this is a server or client session (instead of having to ask {@code instanceof}).
     *
     * @return {@code true} if this is a server session
     */
    boolean isServerSession();

    /**
     * Retrieve the client version for this session.
     *
     * @return the client version - may be {@code null}/empty if versions not yet exchanged
     */
    String getClientVersion();

    /**
     * @return An <U>un-modifiable</U> map of the latest KEX client proposal options May be empty if KEX not yet
     *         completed or re-keying in progress
     * @see    #getKexState()
     */
    Map<KexProposalOption, String> getClientKexProposals();

    /**
     * Retrieve the server version for this session.
     *
     * @return the server version - may be {@code null}/empty if versions not yet exchanged
     */
    String getServerVersion();

    /**
     * @return An <U>un-modifiable</U> map of the latest KEX client proposal options. May be empty if KEX not yet
     *         completed or re-keying in progress
     * @see    #getKexState()
     */
    Map<KexProposalOption, String> getServerKexProposals();

    KexState getKexState();

    Map<KexProposalOption, String> getKexNegotiationResult();

    /**
     * Retrieve one of the negotiated values during the KEX stage
     *
     * @param  paramType The request {@link KexProposalOption} value - ignored if {@code null}
     * @return           The negotiated parameter value - {@code null} if invalid parameter or no negotiated value.
     * @see              #getKexState()
     */
    String getNegotiatedKexParameter(KexProposalOption paramType);

    /**
     * Retrieves current cipher information - <B>Note:</B> may change if key re-exchange executed
     *
     * @param  incoming If {@code true} then the cipher for the incoming data, otherwise for the outgoing data
     * @return          The {@link CipherInformation} - or {@code null} if not negotiated yet.
     */
    CipherInformation getCipherInformation(boolean incoming);

    /**
     * Retrieves current compression information - <B>Note:</B> may change if key re-exchange executed
     *
     * @param  incoming If {@code true} then the compression for the incoming data, otherwise for the outgoing data
     * @return          The {@link CompressionInformation} - or {@code null} if not negotiated yet.
     */
    CompressionInformation getCompressionInformation(boolean incoming);

    /**
     * Retrieves current MAC information - <B>Note:</B> may change if key re-exchange executed
     *
     * @param  incoming If {@code true} then the MAC for the incoming data, otherwise for the outgoing data
     * @return          The {@link MacInformation} - or {@code null} if not negotiated yet.
     */
    MacInformation getMacInformation(boolean incoming);

    /**
     * @return {@code true} if session has successfully completed the authentication phase
     */
    boolean isAuthenticated();

    /**
     * @param  version The reported client/server version
     * @return         {@code true} if version not empty and starts with either {@value #DEFAULT_SSH_VERSION_PREFIX} or
     *                 {@value #FALLBACK_SSH_VERSION_PREFIX}
     */
    static boolean isValidVersionPrefix(String version) {
        return GenericUtils.isNotEmpty(version)
                && (version.startsWith(DEFAULT_SSH_VERSION_PREFIX) || version.startsWith(FALLBACK_SSH_VERSION_PREFIX));
    }

    /**
     * @param  session The {@link SessionContext} to be examined
     * @return         {@code true} if the context is not {@code null} and the ciphers have been established to anything
     *                 other than &quot;none&quot;.
     * @see            #getNegotiatedKexParameter(KexProposalOption) getNegotiatedKexParameter
     * @see            KexProposalOption#CIPHER_PROPOSALS CIPHER_PROPOSALS
     */
    static boolean isSecureSessionTransport(SessionContext session) {
        if (session == null) {
            return false;
        }

        for (KexProposalOption opt : KexProposalOption.CIPHER_PROPOSALS) {
            String value = session.getNegotiatedKexParameter(opt);
            if (GenericUtils.isEmpty(value)
                    || BuiltinCiphers.Constants.NONE.equalsIgnoreCase(value)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param  session The {@link SessionContext} to be examined
     * @return         {@code true} if the context is not {@code null} and the MAC(s) used to verify packet integrity
     *                 have been established.
     * @see            #getNegotiatedKexParameter(KexProposalOption) getNegotiatedKexParameter
     * @see            KexProposalOption#MAC_PROPOSALS MAC_PROPOSALS
     */
    static boolean isDataIntegrityTransport(SessionContext session) {
        if (session == null) {
            return false;
        }

        for (KexProposalOption opt : KexProposalOption.MAC_PROPOSALS) {
            String value = session.getNegotiatedKexParameter(opt);
            if (GenericUtils.isEmpty(value)) {
                return false;
            }
        }

        return true;
    }
}
