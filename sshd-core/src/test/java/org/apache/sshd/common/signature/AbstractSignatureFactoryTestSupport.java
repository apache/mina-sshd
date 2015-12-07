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

package org.apache.sshd.common.signature;

import java.security.KeyPair;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.keyprovider.AbstractKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.After;
import org.junit.Before;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSignatureFactoryTestSupport extends BaseTestSupport {
    private SshServer sshd;
    private SshClient client;
    private int port;

    private final String keyType;
    private final int keySize;

    protected AbstractSignatureFactoryTestSupport(String keyType, int keySize) {
        this.keyType = ValidateUtils.checkNotNullAndNotEmpty(keyType, "No key type specified");
        ValidateUtils.checkTrue(keySize > 0, "Invalid key size: %d", keySize);
        this.keySize = keySize;
    }

    public final int getKeySize() {
        return keySize;
    }

    public final String getKeyType() {
        return keyType;
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
        if (client != null) {
            client.stop();
        }
    }

    protected void testKeyPairProvider(PublicKeyEntryDecoder<?, ?> decoder, List<NamedFactory<Signature>> signatures) throws Exception {
        testKeyPairProvider(getKeyType(), getKeySize(), decoder, signatures);
    }

    protected void testKeyPairProvider(
            final String keyName, final int keySize, final PublicKeyEntryDecoder<?, ?> decoder, List<NamedFactory<Signature>> signatures)
            throws Exception {
        testKeyPairProvider(keyName, new Factory<Iterable<KeyPair>>() {
            @Override
            public Iterable<KeyPair> create() {
                try {
                    KeyPair kp = decoder.generateKeyPair(keySize);
                    outputDebugMessage("Generated key pair for %s - key size=%d", keyName, keySize);
                    return Collections.singletonList(kp);
                } catch (Exception e) {
                    throw new RuntimeSshException(e);
                }
            }
        }, signatures);
    }

    protected void testKeyPairProvider(
            final String keyName, final Factory<Iterable<KeyPair>> factory, List<NamedFactory<Signature>> signatures)
            throws Exception {
        final Iterable<KeyPair> iter = factory.create();
        testKeyPairProvider(new AbstractKeyPairProvider() {
            @Override
            public Iterable<KeyPair> loadKeys() {
                return iter;
            }
        }, signatures);
    }

    protected void testKeyPairProvider(KeyPairProvider provider, List<NamedFactory<Signature>> signatures) throws Exception {
        sshd.setKeyPairProvider(provider);
        sshd.start();
        port = sshd.getPort();

        client = setupTestClient();
        client.setSignatureFactories(signatures);
        client.start();
        try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            s.addPasswordIdentity(getCurrentTestName());
            // allow a rather long timeout since generating some keys may take some time
            s.auth().verify(30L, TimeUnit.SECONDS);
        } finally {
            client.stop();
        }
    }
}
