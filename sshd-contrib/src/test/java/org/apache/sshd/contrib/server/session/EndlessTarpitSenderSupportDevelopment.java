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

package org.apache.sshd.contrib.server.session;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.ReservedSessionMessagesHandler;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.contrib.common.io.EndlessWriteFuture;
import org.apache.sshd.contrib.common.io.ImmediateWriteFuture;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @see    <A HREF="https://nullprogram.com/blog/2019/03/22/">Endless tarpit</A>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class EndlessTarpitSenderSupportDevelopment extends AbstractLoggingBean implements Runnable, SessionListener {
    private static final Collection<EndlessTarpitSenderSupportDevelopment> THREADS = new LinkedList<>();

    private final Random randomizer;
    private final byte[] dataBuffer;
    private final byte[] outputBuffer;
    private AtomicLong numSent = new AtomicLong();
    private final ServerSession session;
    private final AtomicBoolean okToRun = new AtomicBoolean(true);

    private EndlessTarpitSenderSupportDevelopment(ServerSession session, int lineLength) {
        this.session = session;
        this.dataBuffer = new byte[(lineLength * 4) / 6 /* BASE64 */];
        this.outputBuffer = new byte[lineLength + 8 /* some padding */ + 2 /* CRLF */];
        FactoryManager manager = session.getFactoryManager();
        Factory<Random> randomFactory = manager.getRandomFactory();
        this.randomizer = randomFactory.create();
        this.session.addSessionListener(this);
    }

    @Override
    public void sessionException(Session session, Throwable t) {
        terminate("sessionException");
    }

    @Override
    public void sessionDisconnect(
            Session session, int reason, String msg, String language, boolean initiator) {
        terminate("sessionDisconnect");
    }

    @Override
    public void sessionClosed(Session session) {
        terminate("sessionClosed");
    }

    private IoWriteFuture sendRandomLine() throws IOException {
        randomizer.fill(dataBuffer);

        Encoder encoder = Base64.getEncoder();
        int len = encoder.encode(dataBuffer, outputBuffer);
        outputBuffer[len] = (byte) '\r';
        outputBuffer[len + 1] = (byte) '\n';

        byte[] packet = Arrays.copyOf(outputBuffer, len + 2);
        String line = new String(packet, 0, packet.length - 2, StandardCharsets.US_ASCII);
        IoSession networkSession = session.getIoSession();
        IoWriteFuture future = networkSession.writeBuffer(new ByteArrayBuffer(packet));
        long count = numSent.incrementAndGet();
        log.info("sendRandomLine({}) sent line #{}: {}", session, count, line);
        return future;
    }

    @Override
    public void run() {
        try {
            synchronized (THREADS) {
                THREADS.add(this);
            }

            while (okToRun.get()) {
                sendRandomLine();

                synchronized (okToRun) {
                    okToRun.wait(TimeUnit.SECONDS.toMillis(5L));
                }
            }
        } catch (Exception e) {
            log.error("run(" + session + ") failure", e);
        } finally {
            log.info("closing({})", session);
            try {
                session.close(true);
            } finally {
                session.removeSessionListener(this);

                synchronized (THREADS) {
                    THREADS.remove(this);
                }
            }
        }
    }

    private void terminate(Object logHint) {
        boolean terminated;
        synchronized (okToRun) {
            terminated = okToRun.getAndSet(false);
            okToRun.notifyAll();
        }

        if (terminated) {
            log.info("terminate({}) terminated {}", logHint, session);
        }
    }

    //////////////////////////////////////////////////////////////////////////////////

    private static <F extends FactoryManager> F setupTimeouts(F manager) {
        CoreModuleProperties.NIO2_READ_TIMEOUT.set(manager, Duration.ofMinutes(15L));
        CoreModuleProperties.IDLE_TIMEOUT.set(manager, Duration.ZERO);
        CoreModuleProperties.AUTH_TIMEOUT.set(manager, Duration.ZERO);
        return manager;
    }

    private static void startServer(String address, int port) throws Exception {
        try (SshServer server = CoreTestSupportUtils.setupTestServer(EndlessTarpitSenderSupportDevelopment.class);
             BufferedReader stdin = new BufferedReader(
                     new InputStreamReader(new NoCloseInputStream(System.in), Charset.defaultCharset()))) {
            setupTimeouts(server);

            if (GenericUtils.isNotEmpty(address)) {
                server.setHost(address);
            }
            server.setPort(port);
            server.setReservedSessionMessagesHandler(new ReservedSessionMessagesHandler() {
                private final Logger log = LoggerFactory.getLogger(EndlessTarpitSenderSupportDevelopment.class);

                @Override
                @SuppressWarnings("synthetic-access")
                public IoWriteFuture sendIdentification(Session session, String version, List<String> extraLines)
                        throws Exception {
                    EndlessTarpitSenderSupportDevelopment tarpit = new EndlessTarpitSenderSupportDevelopment(
                            (ServerSession) session, 32);
                    Thread thread = new Thread(tarpit, "t" + session.getIoSession().getRemoteAddress());
                    thread.start();
                    log.info("sendIdentification({})[{}] Started endless sender", session, version);
                    return EndlessWriteFuture.INSTANCE;
                }

                @Override
                public IoWriteFuture sendKexInitRequest(
                        Session session, Map<KexProposalOption, String> proposal, Buffer packet)
                        throws Exception {
                    log.info("sendKexInitRequest({}) suppressed KEX sending", session);
                    return new ImmediateWriteFuture(session, packet);
                }

            });
            System.err.append("Starting SSHD on " + address + ":" + port);
            server.start();

            try {
                while (true) {
                    System.out.println("Running on port " + port + " (Q)uit: ");
                    String line = stdin.readLine();
                    line = GenericUtils.trimToEmpty(line);
                    if ("q".equalsIgnoreCase(line) || "quit".equalsIgnoreCase(line)) {
                        break;
                    }
                }
            } finally {
                System.err.append("Stopping server on port ").println(port);
                server.stop();
            }
        } finally {
            for (EndlessTarpitSenderSupportDevelopment t : THREADS) {
                t.terminate("main");
            }
        }
    }

    private static void startClient(String host, int port) throws Exception {
        try (SshClient client = CoreTestSupportUtils.setupTestClient(EndlessTarpitSenderSupportDevelopment.class)) {
            setupTimeouts(client);

            client.addSessionListener(new SessionListener() {
                private final Logger log = LoggerFactory.getLogger(EndlessTarpitSenderSupportDevelopment.class);
                private final AtomicInteger lastCount = new AtomicInteger();

                @Override
                public void sessionEstablished(Session session) {
                    log.info("sessionEstablished({})", session);
                }

                @Override
                public void sessionPeerIdentificationLine(
                        Session session, String line, List<String> extraLines) {
                    if (lastCount.get() < GenericUtils.size(extraLines)) {
                        int num = lastCount.incrementAndGet();
                        log.info("sessionPeerIdentificationLine({})[{}] {}", session, num, line);
                    }
                }

            });

            client.start();
            Duration waitTime = Duration.ofMinutes(15L);
            try (ClientSession session = client.connect(host, host, port)
                    .verify(waitTime)
                    .getSession()) {
                session.addPasswordIdentity(host);
                session.auth().verify(waitTime);
            } finally {
                client.stop();
            }
        }
    }

    // optional args[0]=client/server - default=server, optional args[1]=port (default 22), optional args[2]=listen/connect address (default=localhost)
    public static void main(String[] args) throws Exception {
        int numArgs = GenericUtils.length(args);
        String mode = (numArgs > 0) ? args[0] : "server";
        int port = (numArgs > 1) ? Integer.parseInt(args[1]) : SshConstants.DEFAULT_PORT;
        if ("server".equalsIgnoreCase(mode)) {
            startServer((numArgs > 2) ? args[2] : null, port);
        } else {
            startClient((numArgs > 2) ? args[2] : BaseTestSupport.TEST_LOCALHOST, port);
        }
    }
}
