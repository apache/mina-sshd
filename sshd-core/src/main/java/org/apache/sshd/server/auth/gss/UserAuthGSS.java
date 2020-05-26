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
package org.apache.sshd.server.auth.gss;

import java.util.Objects;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.auth.AbstractUserAuth;
import org.apache.sshd.server.session.ServerSession;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;

/**
 * <p>
 * Prototype user authentication handling gssapi-with-mic. Implements <code>HandshakingUserAuth</code> because the
 * process involves several steps.
 * </p>
 *
 * <p>
 * Several methods are available for overriding in specific circumstances.
 * </p>
 */
public class UserAuthGSS extends AbstractUserAuth {
    public static final String NAME = UserAuthGSSFactory.NAME;

    // Oids for the Kerberos 5 mechanism and principal
    public static final Oid KRB5_MECH = createOID("1.2.840.113554.1.2.2");
    public static final Oid KRB5_NT_PRINCIPAL = createOID("1.2.840.113554.1.2.2.1");

    // The on-going GSS context.
    private GSSContext context;

    // Identity from context
    private String identity;

    public UserAuthGSS() {
        super(NAME);
    }

    @Override
    protected Boolean doAuth(Buffer buffer, boolean initial) throws Exception {
        ServerSession session = getServerSession();
        GSSAuthenticator auth = Objects.requireNonNull(session.getGSSAuthenticator(), "No GSSAuthenticator configured");
        String user = getUsername();
        boolean debugEnabled = log.isDebugEnabled();

        if (initial) {
            // Get mechanism count from buffer and look for Kerberos 5.
            int num = buffer.getInt();
            // Protect against malicious or corrupted packets
            if ((num < 0) || (num > SshConstants.SSH_REQUIRED_PAYLOAD_PACKET_LENGTH_SUPPORT)) {
                log.error("doAuth({}@{}) Illogical OID entries count: {}", user, session, num);
                throw new IndexOutOfBoundsException("Illogical OID entries count: " + num);
            }

            boolean traceEnabled = log.isTraceEnabled();
            for (int i = 1; i <= num; i++) {
                Oid oid = new Oid(buffer.getBytes());
                if (!oid.equals(KRB5_MECH)) {
                    if (traceEnabled) {
                        log.trace("doAuth({}@{}) skip OID {}/{}: {}", user, session, i, num, oid);
                    }
                    continue;
                }
                if (debugEnabled) {
                    log.debug("doAuth({}@{}) found Kerberos 5 after {}/{} OID(s)", user, session, i, num);
                }

                // Validate initial user before proceeding
                if (!auth.validateInitialUser(session, user)) {
                    return Boolean.FALSE;
                }

                GSSManager mgr = auth.getGSSManager();
                GSSCredential creds = auth.getGSSCredential(mgr);
                if (creds == null) {
                    return Boolean.FALSE;
                }

                context = mgr.createContext(creds);

                // Send the matching mechanism back to the client

                byte[] out = oid.getDER();
                Buffer b = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_INFO_REQUEST, out.length + Integer.SIZE);
                b.putBytes(out);
                session.writePacket(b);

                return null;
            }

            // No matching mechanism found
            return Boolean.FALSE;
        } else {
            int msg = buffer.getUByte();
            if (!((msg == SshConstants.SSH_MSG_USERAUTH_INFO_RESPONSE)
                    || ((msg == SshConstants.SSH_MSG_USERAUTH_GSSAPI_MIC)) && context.isEstablished())) {
                throw new SshException(
                        SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                        "Packet not supported by user authentication method: " + SshConstants.getCommandMessageName(msg));
            }

            if (debugEnabled) {
                log.debug("doAuth({}@{}) In krb5.next: msg = {}", user, session, SshConstants.getCommandMessageName(msg));
            }

            // If the context is established, this must be a MIC message

            if (context.isEstablished()) {
                if (msg != SshConstants.SSH_MSG_USERAUTH_GSSAPI_MIC) {
                    return Boolean.FALSE;
                }

                // Make the MIC message so the token can be verified

                Buffer msgbuf = new ByteArrayBuffer();
                msgbuf.putBytes(ValidateUtils.checkNotNullAndNotEmpty(session.getSessionId(), "No current session ID"));
                msgbuf.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
                msgbuf.putString(getUsername());
                msgbuf.putString(getService());
                msgbuf.putString(getName());

                byte[] msgbytes = msgbuf.getCompactData();
                byte[] inmic = buffer.getBytes();
                try {
                    context.verifyMIC(inmic, 0, inmic.length, msgbytes, 0, msgbytes.length, new MessageProp(false));
                    if (debugEnabled) {
                        log.debug("doAuth({}@{}) MIC verified", getUsername(), session);
                    }
                    return Boolean.TRUE;
                } catch (GSSException e) {
                    if (debugEnabled) {
                        log.debug("doAuth({}@{}) GSS verification {} error: {}",
                                user, session, e.getClass().getSimpleName(), e.getMessage());
                    }
                    return Boolean.FALSE;
                }
            } else {
                // Not established - new token to process
                byte[] tok = buffer.getBytes();
                byte[] out = context.acceptSecContext(tok, 0, tok.length);
                boolean established = context.isEstablished();

                // Validate identity if context is now established
                if (established && (identity == null)) {
                    GSSName srcName = context.getSrcName();
                    identity = srcName.toString();
                    if (debugEnabled) {
                        log.debug("doAuth({}@{}) GSS identity is {}", user, session, identity);
                    }

                    if (!auth.validateIdentity(session, identity)) {
                        return Boolean.FALSE;
                    }
                }

                // Send return token if necessary
                if (NumberUtils.length(out) > 0) {
                    Buffer b = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_INFO_RESPONSE, out.length + Integer.SIZE);
                    b.putBytes(out);
                    session.writePacket(b);
                    return null;
                } else {
                    return established;
                }
            }
        }
    }

    /**
     * Free any system resources used by the module.
     */
    @Override
    public void destroy() {
        if (context != null) {
            try {
                context.dispose();
            } catch (GSSException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Failed ({}) to dispose of context: {}", e.getClass().getSimpleName(), e.getMessage());
                }
            } finally {
                context = null;
            }
        }
    }

    /**
     * Utility to construct an Oid from a string, ignoring the annoying exception.
     *
     * @param  rep The string form
     * @return     The Oid
     */
    public static Oid createOID(String rep) {
        try {
            return new Oid(rep);
        } catch (GSSException e) {
            // won't happen
            return null;
        }
    }
}
