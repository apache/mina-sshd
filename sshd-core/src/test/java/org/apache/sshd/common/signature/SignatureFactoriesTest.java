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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.config.keys.impl.DSSPublicKeyEntryDecoder;
import org.apache.sshd.common.config.keys.impl.ECDSAPublicKeyEntryDecoder;
import org.apache.sshd.common.config.keys.impl.RSAPublicKeyDecoder;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.keyprovider.KeySizeIndicator;
import org.apache.sshd.common.keyprovider.KeyTypeIndicator;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
public class SignatureFactoriesTest extends BaseTestSupport implements KeyTypeIndicator, KeySizeIndicator, OptionalFeature {
    private static SshServer sshd;
    private static SshClient client;
    private static int port;

    private final String keyType;
    private final int keySize;
    private final boolean supported;
    private final NamedFactory<Signature> factory;
    private final PublicKeyEntryDecoder<?, ?> pubKeyDecoder;

    public SignatureFactoriesTest(
                                  String keyType, NamedFactory<Signature> factory,
                                  int keySize, boolean supported, PublicKeyEntryDecoder<?, ?> decoder) {
        this.keyType = ValidateUtils.checkNotNullAndNotEmpty(keyType, "No key type specified");
        this.factory = supported ? Objects.requireNonNull(factory, "No signature factory provided") : factory;
        if (supported) {
            ValidateUtils.checkTrue(keySize > 0, "Invalid key size: %d", keySize);
        }
        this.keySize = keySize;
        this.supported = supported;
        this.pubKeyDecoder = supported ? Objects.requireNonNull(decoder, "No public key decoder provided") : null;
    }

    @Parameters(name = "type={0}, size={2}")
    @SuppressWarnings("deprecation")
    public static List<Object[]> parameters() {
        List<Object[]> list = new ArrayList<>();
        addTests(list, KeyPairProvider.SSH_DSS, BuiltinSignatures.dsa, DSS_SIZES, DSSPublicKeyEntryDecoder.INSTANCE);
        addTests(list, KeyPairProvider.SSH_RSA, BuiltinSignatures.rsa, RSA_SIZES, RSAPublicKeyDecoder.INSTANCE);

        if (SecurityUtils.isECCSupported()) {
            for (ECCurves curve : ECCurves.VALUES) {
                BuiltinSignatures factory = BuiltinSignatures.fromFactoryName(curve.getKeyType());
                addTests(list, curve.getName(), factory,
                        curve.isSupported() ? Collections.singletonList(curve.getKeySize()) : Collections.singletonList(-1),
                        curve.isSupported() ? ECDSAPublicKeyEntryDecoder.INSTANCE : null);
            }
        } else {
            for (String name : ECCurves.NAMES) {
                addTests(list, name, null, Collections.singletonList(-1), null);
            }
        }
        addTests(list, KeyPairProvider.SSH_ED25519, BuiltinSignatures.ed25519, ED25519_SIZES,
                SecurityUtils.isEDDSACurveSupported() ? SecurityUtils.getEDDSAPublicKeyEntryDecoder() : null);
        return Collections.unmodifiableList(list);
    }

    private static void addTests(
            List<Object[]> list, String keyType, NamedFactory<Signature> factory, Collection<Integer> sizes,
            PublicKeyEntryDecoder<?, ?> decoder) {
        for (Integer keySize : sizes) {
            list.add(new Object[] { keyType, factory, keySize, decoder != null, decoder });
        }
    }

    @BeforeClass
    public static void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestFullSupportServer(SignatureFactoriesTest.class);
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestFullSupportClient(SignatureFactoriesTest.class);
        client.start();
    }

    @AfterClass
    public static void tearDownClientAndServer() throws Exception {
        if (sshd != null) {
            try {
                sshd.stop(true);
            } finally {
                sshd = null;
            }
        }

        if (client != null) {
            try {
                client.stop();
            } finally {
                client = null;
            }
        }
    }

    @Override
    public final boolean isSupported() {
        return supported;
    }

    @Override
    public final int getKeySize() {
        return keySize;
    }

    @Override
    public final String getKeyType() {
        return keyType;
    }

    @Test
    public void testPublicKeyAuth() throws Exception {
        Assume.assumeTrue(isSupported());
        testKeyPairProvider(getKeyType(), getKeySize(), pubKeyDecoder, Collections.singletonList(factory));
    }

    protected void testKeyPairProvider(
            String keyName, int keySize, PublicKeyEntryDecoder<?, ?> decoder, List<NamedFactory<Signature>> signatures)
            throws Exception {
        testKeyPairProvider(keyName, () -> {
            try {
                KeyPair kp = decoder.generateKeyPair(keySize);
                outputDebugMessage("Generated key pair for %s - key size=%d", keyName, keySize);
                return Collections.singletonList(kp);
            } catch (Exception e) {
                throw new RuntimeSshException(e);
            }
        }, signatures);
    }

    protected void testKeyPairProvider(
            String keyName, Factory<Iterable<KeyPair>> keyPairFactory, List<NamedFactory<Signature>> signatures)
            throws Exception {
        Iterable<KeyPair> iter = keyPairFactory.create();
        testKeyPairProvider(new KeyPairProvider() {
            @Override
            public Iterable<KeyPair> loadKeys(SessionContext session) {
                return iter;
            }
        }, signatures);
    }

    protected void testKeyPairProvider(
            KeyPairProvider provider, List<NamedFactory<Signature>> signatures)
            throws Exception {
        sshd.setKeyPairProvider(provider);
        client.setSignatureFactories(signatures);
        try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT).getSession()) {
            s.addPasswordIdentity(getCurrentTestName());
            // allow a rather long timeout since generating some keys may take some time
            s.auth().verify(AUTH_TIMEOUT.multipliedBy(3));
        }
    }
}
