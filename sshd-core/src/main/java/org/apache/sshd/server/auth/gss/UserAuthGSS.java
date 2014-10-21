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
package org.apache.sshd.server.auth.gss;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.auth.AbstractUserAuth;
import org.apache.sshd.server.session.ServerSession;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;

/**
 * <p>Prototype user authentication handling gssapi-with-mic.  Implements <code>HandshakingUserAuth</code> because
 * the process involves several steps.</p>
 *
 * <p>Several methods are available for overriding in specific circumstances.</p>
 */
public class UserAuthGSS extends AbstractUserAuth {

    // Oids for the Kerberos 5 mechanism and principal

    public static final Oid KRB5_MECH = createOID("1.2.840.113554.1.2.2");
    public static final Oid KRB5_NT_PRINCIPAL = createOID("1.2.840.113554.1.2.2.1");

    // The on-going GSS context.
    private GSSContext context;

    // Identity from context
    private String identity;

    /**
     * Handle the first authentication step.
     */
    protected Boolean doAuth(Buffer buffer, boolean initial) throws Exception {
        GSSAuthenticator auth = getAuthenticator(session);

        if (initial) {
            // Get mechanism count from buffer and look for Kerberos 5.

            int num = buffer.getInt();

            for (int i = 0; i < num; i++) {
                Oid oid = new Oid(buffer.getBytes());

                if (oid.equals(KRB5_MECH)) {
                    log.debug("UserAuthGSS: found Kerberos 5");

                    // Validate initial user before proceeding

                    if (!auth.validateInitialUser(session, username)) {
                        return Boolean.FALSE;
                    }

                    GSSManager mgr = auth.getGSSManager();
                    GSSCredential creds = auth.getGSSCredential(mgr);

                    if (creds == null) {
                        return Boolean.FALSE;
                    }

                    context = mgr.createContext(creds);

                    // Send the matching mechanism back to the client

                    Buffer b = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_INFO_REQUEST);
                    byte[] out = oid.getDER();

                    b.putBytes(out);
                    session.writePacket(b);

                    return null;
                }
            }

            // No matching mechanism found

            return Boolean.FALSE;
        }
        else
        {
            byte msg = buffer.getByte();
            if (!(msg == SshConstants.SSH_MSG_USERAUTH_INFO_RESPONSE ||
                    msg == SshConstants.SSH_MSG_USERAUTH_GSSAPI_MIC && context.isEstablished())) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                        "Packet not supported by user authentication method");
            }

            log.debug("In krb5.next: msg = " + msg);

            // If the context is established, this must be a MIC message

            if (context.isEstablished()) {

                if (msg != SshConstants.SSH_MSG_USERAUTH_GSSAPI_MIC) {
                    return Boolean.FALSE;
                }

                // Make the MIC message so the token can be verified

                Buffer msgbuf = new Buffer();

                msgbuf.putString(session.getSessionId());
                msgbuf.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
                msgbuf.putString(username.getBytes("UTF-8"));
                msgbuf.putString(service);
                msgbuf.putString("gssapi-with-mic");

                byte[] msgbytes = msgbuf.getCompactData();
                byte[] inmic = buffer.getBytes();

                try {
                    context.verifyMIC(inmic, 0, inmic.length, msgbytes, 0, msgbytes.length, new MessageProp(false));
                    log.debug("MIC verified");
                    return Boolean.TRUE;
                } catch (GSSException e) {
                    log.info("GSS verification error: {}", e.toString());
                    return Boolean.FALSE;
                }

            } else {

                // Not established - new token to process

                byte[] tok = buffer.getBytes();
                byte[] out = context.acceptSecContext(tok, 0, tok.length);
                boolean established = context.isEstablished();

                // Validate identity if context is now established

                if (established && identity == null) {
                    identity = context.getSrcName().toString();
                    log.info("GSS identity is {}", identity);

                    if (!auth.validateIdentity(session, identity)) {
                        return Boolean.FALSE;
                    }
                }

                // Send return token if necessary

                if (out != null && out.length > 0) {
                    Buffer b = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_INFO_RESPONSE);

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
     * Get a user name which has been derived from the handshaking process, or the initial name if
     * nothing has been found.
     *
     * @return The user name
     */
    public String getUserName() {
        return identity != null ? identity : username;
    }

    /**
     * Free any system resources used by the module.
     */
    public void destroy() {
        if (context != null) {
            try {
                context.dispose();
            } catch (GSSException e) {
                // ignore
            } finally {
                context = null;
            }
        }
    }

    /**
     * Utility to get the configured GSS authenticator for the server, throwing an exception if none is available.
     *
     * @param session The current session
     * @return The GSS authenticator
     * @throws Exception If no GSS authenticator is defined
     */
    private GSSAuthenticator getAuthenticator(ServerSession session) throws Exception {
        GSSAuthenticator ga = session.getFactoryManager().getGSSAuthenticator();

        if (ga == null) {
            throw new Exception("No GSSAuthenticator configured");
        } else {
            return ga;
        }
    }

    /**
     * Utility to construct an Oid from a string, ignoring the annoying exception.
     *
     * @param rep The string form
     * @return The Oid
     */
    private static Oid createOID(String rep) {
        try {
            return new Oid(rep);
        } catch (GSSException e) {
            // won't happen
            return null;
        }
    }

    /**
     * Factory class.
     */
    public static class Factory implements NamedFactory<UserAuth> {

        /**
         * Get the name of the authentication method.
         *
         * @return Tge name, always 'gssapi-with-mic' here.
         */
        public String getName() {
            return "gssapi-with-mic";
        }

        /**
         * Create a new authenticator instance.
         *
         * @return The instance
         */
        public UserAuth create() {
            return new UserAuthGSS();
        }
    }
}
