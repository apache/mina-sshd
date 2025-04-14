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
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.Arrays;
import java.util.concurrent.CancellationException;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * An abstract implementation of a username-password authentication. It can be given an initial known username-password
 * pair; if so, this will be tried first. Subsequent rounds will then try to obtain a user name and password via the
 * global {@link Authenticator}.
 *
 * @param <P> defining the parameter type for the authentication
 * @param <T> defining the token type for the authentication
 */
public abstract class BasicAuthentication<P, T> extends AbstractAuthenticationHandler<P, T> {

    /** The current user name. */
    protected String user;

    /** The current password. */
    protected byte[] password;

    /**
     * Creates a new {@link BasicAuthentication} to authenticate with the given {@code proxy}.
     *
     * @param proxy           {@link InetSocketAddress} of the proxy to connect to
     * @param initialUser     initial user name to try; may be {@code null}
     * @param initialPassword initial password to try, may be {@code null}
     */
    protected BasicAuthentication(InetSocketAddress proxy, String initialUser, char[] initialPassword) {
        super(proxy);
        this.user = initialUser;
        this.password = convert(initialPassword);
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private byte[] convert(char[] pass) {
        if (pass == null) {
            return new byte[0];
        }
        ByteBuffer bytes = UTF_8.encode(CharBuffer.wrap(pass));
        byte[] pwd = new byte[bytes.remaining()];
        bytes.get(pwd);
        if (bytes.hasArray()) {
            Arrays.fill(bytes.array(), (byte) 0);
        }
        Arrays.fill(pass, '\000');
        return pwd;
    }

    /**
     * Clears the {@link #password}.
     */
    protected void clearPassword() {
        if (password != null) {
            Arrays.fill(password, (byte) 0);
        }
        password = new byte[0];
    }

    @Override
    public final void close() {
        clearPassword();
        done = true;
    }

    @Override
    public final void start() throws IOException {
        if ((user != null && !user.isEmpty()) || (password != null && password.length > 0)) {
            return;
        }
        askCredentials();
    }

    @Override
    public void process() throws Exception {
        askCredentials();
    }

    /**
     * Asks for credentials via the global {@link Authenticator}.
     */
    protected void askCredentials() {
        clearPassword();
        PasswordAuthentication auth = getCredentials();
        if (auth == null) {
            user = ""; //$NON-NLS-1$
            throw new CancellationException("Proxy authentication cancelled by user");
        }
        user = auth.getUserName();
        password = convert(auth.getPassword());
    }

    protected abstract PasswordAuthentication getCredentials();
}
