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
package org.apache.sshd.common.compression;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;

import com.jcraft.jsch.JSch;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.JSchLogger;
import org.apache.sshd.util.test.SimpleUserInfo;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * Test compression algorithms.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class)   // see https://github.com/junit-team/junit/wiki/Parameterized-tests
public class CompressionTest extends BaseTestSupport {
    private static final Collection<KexProposalOption> COMPRESSION_OPTIONS =
            Collections.unmodifiableSet(EnumSet.of(KexProposalOption.C2SCOMP, KexProposalOption.S2CCOMP));

    private final CompressionFactory factory;
    private SshServer sshd;

    public CompressionTest(CompressionFactory factory) {
        this.factory = factory;
    }

    @Parameters(name = "factory={0}")
    public static List<Object[]> parameters() {
        return parameterize(BuiltinCompressions.VALUES);
    }

    @BeforeClass
    public static void jschInit() {
        JSchLogger.init();
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        sshd.setCompressionFactories(Arrays.<NamedFactory<org.apache.sshd.common.compression.Compression>>asList(factory));
        sshd.addSessionListener(new SessionListener() {
            @Override
            public void sessionException(Session session, Throwable t) {
                // ignored
            }

            @Override
            @SuppressWarnings("synthetic-access")
            public void sessionEvent(Session session, Event event) {
                if (Event.KeyEstablished.equals(event)) {
                    String expected = factory.getName();
                    for (KexProposalOption option : COMPRESSION_OPTIONS) {
                        String actual = session.getNegotiatedKexParameter(KexProposalOption.C2SCOMP);
                        assertEquals("Mismatched value for " + option, expected, actual);
                    }
                }
            }

            @Override
            public void sessionCreated(Session session) {
                // ignored
            }

            @Override
            public void sessionClosed(Session session) {
                // ignored
            }
        });
        sshd.start();

        String name = factory.getName();
        JSch.setConfig("compression.s2c", name);
        JSch.setConfig("compression.c2s", name);
        JSch.setConfig("zlib", com.jcraft.jsch.jcraft.Compression.class.getName());
        JSch.setConfig("zlib@openssh.com", com.jcraft.jsch.jcraft.Compression.class.getName());
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
        JSch.setConfig("compression.s2c", "none");
        JSch.setConfig("compression.c2s", "none");
    }

    @Test
    public void testCompression() throws Exception {
        Assume.assumeTrue("Skip unsupported compression " + factory, factory.isSupported());

        JSch sch = new JSch();
        com.jcraft.jsch.Session s = sch.getSession(getCurrentTestName(), TEST_LOCALHOST, sshd.getPort());
        s.setUserInfo(new SimpleUserInfo(getCurrentTestName()));

        s.connect();
        try {
            com.jcraft.jsch.Channel c = s.openChannel(Channel.CHANNEL_SHELL);
            c.connect();
            try (OutputStream os = c.getOutputStream();
                 InputStream is = c.getInputStream()) {

                String testCommand = "this is my command\n";
                byte[] bytes = testCommand.getBytes(StandardCharsets.UTF_8);
                byte[] data = new byte[bytes.length + Long.SIZE];
                for (int i = 1; i <= 10; i++) {
                    os.write(bytes);
                    os.flush();

                    int len = is.read(data);
                    String str = new String(data, 0, len, StandardCharsets.UTF_8);
                    assertEquals("Mismatched read data at iteration #" + i, testCommand, str);
                }
            } finally {
                c.disconnect();
            }
        } finally {
            s.disconnect();
        }
    }
}
