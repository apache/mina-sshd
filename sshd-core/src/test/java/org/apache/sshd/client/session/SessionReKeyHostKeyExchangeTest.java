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
package org.apache.sshd.client.session;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.common.channel.StreamingChannel;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionHeartbeatController;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.ContainerTestCase;
import org.hamcrest.Description;
import org.hamcrest.MatcherAssert;
import org.hamcrest.TypeSafeDiagnosingMatcher;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;

@Category(ContainerTestCase.class)
public class SessionReKeyHostKeyExchangeTest extends BaseTestSupport {

    private static final Logger LOG = LoggerFactory.getLogger(SessionReKeyHostKeyExchangeTest.class);

    @Rule
    public GenericContainer<?> sshdContainer = new GenericContainer<>(
            new ImageFromDockerfile()
                    .withDockerfileFromBuilder(builder -> builder
                            // With alpine, which installs newer OpenSSH versions, SSHD-1264 does not occur.
                            .from("centos:7.9.2009") // So use CentOS, even if it's much slower
                            .run("yum install -y openssh-server") // Installs OpenSSH 7.4
                            .run("/usr/sbin/sshd-keygen") // Generate multiple host keys
                            .run("adduser bob") // Add a user
                            .run("echo \"123qweASD\" | passwd bob --stdin") // Give the user a password
                            .run("echo RekeyLimit default 1 >> /etc/ssh/sshd_config") // Re-key every second
                            .entryPoint("/usr/sbin/sshd", "-D", "-ddd") //
                            .build()))
                                    .waitingFor(Wait.forLogMessage(".*Server listening on :: port 22.*\\n", 1))
                                    .withExposedPorts(22) //
                                    .withLogConsumer(new Slf4jLogConsumer(LOG));

    public SessionReKeyHostKeyExchangeTest() {
        super();
    }

    @Test // https://issues.apache.org/jira/browse/SSHD-1264
    public void testRekeyUsesSameHostKeyAlgorithm() throws Exception {
        LOG.info("*************************************************************************************");
        SshClient client = SshClient.setUpDefaultClient();
        AcceptFirstAlgorithmHostKeyVerifier hostKeyVerifier = new AcceptFirstAlgorithmHostKeyVerifier();
        client.setServerKeyVerifier(hostKeyVerifier);

        try {
            client.start();
            try (ClientSession session = client.connect("bob", sshdContainer.getHost(), sshdContainer.getMappedPort(22))
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity("123qweASD");
                assertTrue("Could not authenticate", session.auth().await(AUTH_TIMEOUT));
                session.setSessionHeartbeat(SessionHeartbeatController.HeartbeatType.IGNORE, TimeUnit.MILLISECONDS, 1);

                try (ChannelShell channel = session.createShellChannel()) {
                    channel.setOut(System.out);
                    channel.setErr(System.err);
                    channel.setStreaming(StreamingChannel.Streaming.Sync);
                    PipedOutputStream pos = new PipedOutputStream();
                    PipedInputStream pis = new PipedInputStream(pos);
                    channel.setIn(pis);
                    assertTrue("Could not open session", channel.open().await(DEFAULT_TIMEOUT));
                    for (int i = 0; i < 20; i++) {
                        Thread.sleep(1000);
                        LOG.info("writing some data...");
                        pos.write("\n\n".getBytes(StandardCharsets.UTF_8));
                    }
                    channel.close(true);
                } catch (IOException e) {
                    // When KEX fails, we most likely get an exception on the PipedInputStream.
                    // Let's produce a halfway reasonable test failure.
                    assertEquals("Expected no host key changes in KEX", 0, hostKeyVerifier.errors);
                    throw new AssertionError("Exception in test", e);
                }
                Thread.sleep(5_000);
                assertTrue("Session should still be open", session.isOpen());
            }
            // We should have about 25 key exchanges, but anything greater than 10 is fine.
            MatcherAssert.assertThat("Not enough re-key attempts", hostKeyVerifier.verifications,
                    AtLeastMatcher.greaterThan(10));
        } finally {
            client.stop();
        }

    }

    private static class AcceptFirstAlgorithmHostKeyVerifier implements ServerKeyVerifier {

        volatile int errors;

        volatile int verifications;

        private PublicKey hostKey;

        AcceptFirstAlgorithmHostKeyVerifier() {
            super();
        }

        @Override
        public boolean verifyServerKey(ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey) {
            if (hostKey == null) {
                // first connect to this host we allow it and store the host key
                hostKey = serverKey;
                LOG.info("**** Accepting initial connection with host key algorithm {}", serverKey.getAlgorithm());
                verifications++;
                return true;
            }

            boolean sameKey = KeyUtils.compareKeys(hostKey, serverKey);
            if (sameKey) {
                LOG.info("Accepting subsequent hostkey, same as in initial connection");
            } else {
                LOG.error("**** Rejecting subsequent host key of type {}, inital host key was {}", serverKey.getAlgorithm(),
                        hostKey.getAlgorithm());
                errors++;
            }
            verifications++;
            return sameKey;
        }
    }

    private static final class AtLeastMatcher extends TypeSafeDiagnosingMatcher<Integer> {

        private final int atLeast;

        private AtLeastMatcher(int atLeast) {
            this.atLeast = atLeast;
        }

        @Override
        protected boolean matchesSafely(Integer item, Description mismatchDescription) {
            mismatchDescription.appendValue(item);
            return atLeast <= item.intValue();
        }

        @Override
        public void describeTo(Description description) {
            description.appendText("a number greater than ").appendValue(atLeast);
        }

        public static AtLeastMatcher greaterThan(int atLeast) {
            return new AtLeastMatcher(atLeast);
        }
    }
}
