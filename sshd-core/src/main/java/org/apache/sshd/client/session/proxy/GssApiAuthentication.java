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
package org.apache.sshd.client.session.proxy;

import java.io.IOException;
import java.net.InetSocketAddress;

import org.ietf.jgss.GSSContext;

/**
 * An abstract implementation of a GSS-API multi-round authentication.
 *
 * @param <P> defining the parameter type for the authentication
 * @param <T> defining the token type for the authentication
 */
public abstract class GssApiAuthentication<P, T> extends AbstractAuthenticationHandler<P, T> {

    /** The last token generated. */
    protected byte[] token;

    private GSSContext context;

    /**
     * Creates a new {@link GssApiAuthentication} to authenticate with the given {@code proxy}.
     *
     * @param proxy the {@link InetSocketAddress} of the proxy to connect to
     */
    protected GssApiAuthentication(InetSocketAddress proxy) {
        super(proxy);
    }

    @Override
    public void close() {
        GssApiMechanisms.closeContextSilently(context);
        context = null;
        done = true;
    }

    @Override
    public final void start() throws IOException {
        try {
            context = createContext();
            context.requestMutualAuth(true);
            context.requestConf(false);
            context.requestInteg(false);
            byte[] empty = new byte[0];
            token = context.initSecContext(empty, 0, 0);
        } catch (Exception e) {
            close();
            throw new IOException(e);
        }
    }

    @Override
    public final void process() throws Exception {
        if (context == null) {
            throw new IOException("Cannot authenticate using GSS-API at " + proxy);
        }
        try {
            byte[] received = extractToken(params);
            token = context.initSecContext(received, 0, received.length);
            checkDone();
        } catch (Exception e) {
            close();
            throw e;
        }
    }

    private void checkDone() throws Exception {
        done = context.isEstablished();
        if (done) {
            context.dispose();
            context = null;
        }
    }

    /**
     * Creates the {@link GSSContext} to use.
     *
     * @return           a fresh {@link GSSContext} to use
     * @throws Exception if the context cannot be created
     */
    protected abstract GSSContext createContext() throws Exception;

    /**
     * Extracts the token from the last set parameters.
     *
     * @param  input     to extract the token from
     * @return           the extracted token, or {@code null} if none
     * @throws Exception if an error occurs
     */
    protected abstract byte[] extractToken(P input) throws Exception;
}
