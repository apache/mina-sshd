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
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.function.Function;

import org.apache.sshd.client.proxy.ProxyData;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.functors.IOFunction;
import org.ietf.jgss.GSSContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Simple HTTP proxy connector supporting Basic and SPNEGO Authentication.
 */
@SuppressWarnings("checkstyle:MethodCount")
public class HttpProxyConnector extends AbstractProxyConnector {

    private static final Logger LOG = LoggerFactory.getLogger(HttpProxyConnector.class);

    private static final String HTTP_V11 = "HTTP/1.1";

    private static final String HTTP_HEADER_PROXY_AUTHENTICATE = "Proxy-Authenticate:";

    private static final String HTTP_HEADER_PROXY_AUTHORIZATION = "Proxy-Authorization:";

    private HttpAuthenticationHandler basic;

    private HttpAuthenticationHandler negotiate;

    private List<HttpAuthenticationHandler> availableAuthentications;

    private Iterator<HttpAuthenticationHandler> clientAuthentications;

    private HttpAuthenticationHandler authenticator;

    private boolean ongoing;

    /**
     * Creates a new {@link HttpProxyConnector}. The connector supports anonymous proxy connections as well as Basic and
     * Negotiate (SPNEGO) authentication.
     *
     * @param proxy         {@link ProxyData} of the proxy we're connected to
     * @param remoteAddress {@link InetSocketAddress} of the target server to connect to
     * @param send          a function to send data and returning an {@link IoWriteFuture}
     * @param passwordAuth  a function to query the user for proxy credentials, if needed, and returning a
     *                      {@link PasswordAuthentication}
     */
    public HttpProxyConnector(ProxyData proxy, InetSocketAddress remoteAddress, IOFunction<Buffer, IoWriteFuture> send,
                              Function<InetSocketAddress, PasswordAuthentication> passwordAuth) {
        super(proxy, remoteAddress, send, passwordAuth);
        basic = new HttpBasicAuthentication();
        negotiate = new NegotiateAuthentication();
        availableAuthentications = new ArrayList<>(2);
        availableAuthentications.add(negotiate);
        availableAuthentications.add(basic);
        clientAuthentications = availableAuthentications.iterator();
    }

    @Override
    public void close() {
        super.close();
        HttpAuthenticationHandler current = authenticator;
        authenticator = null;
        if (current != null) {
            current.close();
        }
    }

    @Override
    public void start() throws IOException {
        StringBuilder msg = connect();
        if ((proxyUser != null && !proxyUser.isEmpty()) || (proxyPassword != null && proxyPassword.length > 0)) {
            authenticator = basic;
            basic.setParams(null);
            basic.start();
            msg = authenticate(msg, basic.getToken());
            clearPassword();
            proxyUser = null;
        }
        ongoing = true;
        try {
            send(msg);
        } catch (IOException e) {
            ongoing = false;
            throw e;
        }
    }

    private void send(StringBuilder msg) throws IOException {
        byte[] data = eol(msg).toString().getBytes(US_ASCII);
        Buffer buffer = new ByteArrayBuffer(data.length, false);
        buffer.putRawBytes(data);
        write(buffer);
    }

    private StringBuilder connect() {
        StringBuilder msg = new StringBuilder();
        // Persistent connections are the default in HTTP 1.1 (see RFC 2616), but let's be explicit.
        return msg.append(MessageFormat.format(
                "CONNECT {0}:{1} {2}\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nHost: {0}:{1}\r\n",
                remoteAddress.getHostString(), Integer.toString(remoteAddress.getPort()), HTTP_V11));
    }

    private StringBuilder authenticate(StringBuilder msg, String token) {
        msg.append(HTTP_HEADER_PROXY_AUTHORIZATION).append(' ').append(token);
        return eol(msg);
    }

    private StringBuilder eol(StringBuilder msg) {
        return msg.append('\r').append('\n');
    }

    @Override
    public Buffer received(Readable buffer) throws Exception {
        try {
            int length = buffer.available();
            byte[] data = new byte[length];
            buffer.getRawBytes(data, 0, length);
            Buffer rest = null;
            // HTTP responses end with two CRLFs. Find them.
            String msg = new String(data, US_ASCII);
            int end = msg.indexOf("\r\n\r\n");
            if (end < 0) {
                end = data.length;
            } else {
                end += 4;
            }
            if (end < data.length) {
                msg = msg.substring(0, end);
                data = Arrays.copyOfRange(data, end, data.length);
                rest = new ByteArrayBuffer(data);
            }
            String[] reply = msg.split("\r\n");
            handleMessage(Arrays.asList(reply));
            return rest;
        } catch (Exception e) {
            if (authenticator != null) {
                authenticator.close();
                authenticator = null;
            }
            ongoing = false;
            done = true;
            throw e;
        }
    }

    private void handleMessage(List<String> reply) throws Exception {
        if (reply.isEmpty() || reply.get(0).isEmpty()) {
            throw new IOException("Unexpected empty reply from proxy " + proxyAddress);
        }
        try {
            StatusLine status = HttpParser.parseStatusLine(reply.get(0));
            if (!ongoing) {
                throw new IOException(MessageFormat.format("Unexpected reply from proxy {0}; {1} status {2}: {3}", proxyAddress,
                        status.getVersion(), Integer.toString(status.getResultCode()), status.getReason()));
            }
            switch (status.getResultCode()) {
                case HttpURLConnection.HTTP_OK:
                    if (authenticator != null) {
                        authenticator.close();
                    }
                    authenticator = null;
                    ongoing = false;
                    done = true;
                    break;
                case HttpURLConnection.HTTP_PROXY_AUTH:
                    boolean closesConnection = reply.stream().anyMatch("Connection: close"::equals);
                    if (closesConnection) {
                        LOG.warn("{} proxy closed connection; needs up-front pre-emptive proxy authentication",
                                status.getVersion());
                    }
                    List<AuthenticationChallenge> challenges = HttpParser.getAuthenticationHeaders(reply,
                            HTTP_HEADER_PROXY_AUTHENTICATE);
                    authenticator = selectProtocol(challenges, authenticator);
                    if (authenticator == null) {
                        throw new IOException("Cannot authenticate at proxy " + proxyAddress);
                    }
                    String token = authenticator.getToken();
                    if (token == null) {
                        throw new IOException("Cannot authenticate at proxy " + proxyAddress);
                    }
                    send(authenticate(connect(), token));
                    break;
                default:
                    throw new IOException(MessageFormat.format("HTTP proxy failure at {0}, HTTP status {1}: {2}", proxyAddress,
                            Integer.toString(status.getResultCode()), status.getReason()));
            }
        } catch (HttpParser.ParseException e) {
            throw new IOException(MessageFormat.format("Cannot parse reply from proxy {0}: {1}", proxyAddress, reply.get(0)),
                    e);
        }
    }

    private HttpAuthenticationHandler selectProtocol(
            List<AuthenticationChallenge> challenges,
            HttpAuthenticationHandler current) throws Exception {
        if (current != null && !current.isDone()) {
            AuthenticationChallenge challenge = getByName(challenges, current.getName());
            if (challenge != null) {
                current.setParams(challenge);
                current.process();
                return current;
            }
        }
        if (current != null) {
            current.close();
        }
        while (clientAuthentications.hasNext()) {
            HttpAuthenticationHandler next = clientAuthentications.next();
            if (!next.isDone()) {
                AuthenticationChallenge challenge = getByName(challenges, next.getName());
                if (challenge != null) {
                    next.setParams(challenge);
                    next.start();
                    return next;
                }
            }
        }
        return null;
    }

    private AuthenticationChallenge getByName(List<AuthenticationChallenge> challenges, String name) {
        return challenges.stream().filter(c -> c.getMechanism().equalsIgnoreCase(name)).findFirst().orElse(null);
    }

    private interface HttpAuthenticationHandler extends AuthenticationHandler<AuthenticationChallenge, String> {

        String getName();
    }

    /**
     * @see <a href="https://tools.ietf.org/html/rfc7617">RFC 7617</a>
     */
    private class HttpBasicAuthentication extends BasicAuthentication<AuthenticationChallenge, String>
            implements HttpAuthenticationHandler {

        private boolean asked;

        HttpBasicAuthentication() {
            super(proxyAddress, proxyUser, proxyPassword);
        }

        @Override
        public String getName() {
            return "Basic";
        }

        @Override
        protected void askCredentials() {
            // We ask only once.
            if (asked) {
                throw new IllegalStateException("Basic auth: already asked user for password");
            }
            asked = true;
            super.askCredentials();
            done = true;
        }

        @Override
        protected PasswordAuthentication getCredentials() {
            return passwordAuthentication();
        }

        @Override
        public String getToken() throws IOException {
            if (user.indexOf(':') >= 0) {
                throw new IOException(MessageFormat.format("Invalid user name ''{0}'' for proxy {1}", user, proxy));
            }
            byte[] rawUser = user.getBytes(UTF_8);
            byte[] toEncode = new byte[rawUser.length + 1 + password.length];
            System.arraycopy(rawUser, 0, toEncode, 0, rawUser.length);
            toEncode[rawUser.length] = ':';
            System.arraycopy(password, 0, toEncode, rawUser.length + 1, password.length);
            Arrays.fill(password, (byte) 0);
            String result = Base64.getEncoder().encodeToString(toEncode);
            Arrays.fill(toEncode, (byte) 0);
            return getName() + ' ' + result;
        }

    }

    /**
     * @see <a href="https://tools.ietf.org/html/rfc4559">RFC 4559</a>
     */
    private class NegotiateAuthentication extends GssApiAuthentication<AuthenticationChallenge, String>
            implements HttpAuthenticationHandler {

        NegotiateAuthentication() {
            super(proxyAddress);
        }

        @Override
        public String getName() {
            return "Negotiate";
        }

        @Override
        public String getToken() {
            return getName() + ' ' + Base64.getEncoder().encodeToString(token);
        }

        @Override
        protected GSSContext createContext() throws Exception {
            return GssApiMechanisms.createContext(GssApiMechanisms.SPNEGO, GssApiMechanisms.getCanonicalName(proxyAddress));
        }

        @Override
        protected byte[] extractToken(AuthenticationChallenge input) {
            String received = input.getToken();
            if (received == null) {
                return new byte[0];
            }
            return Base64.getDecoder().decode(received);
        }

    }
}
