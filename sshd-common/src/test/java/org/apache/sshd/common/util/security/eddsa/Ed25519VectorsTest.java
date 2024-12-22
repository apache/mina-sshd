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

package org.apache.sshd.common.util.security.eddsa;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.eddsa.bouncycastle.BouncyCastleEdDSASupport;
import org.apache.sshd.common.util.security.eddsa.generic.EdDSASupport;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-02#section-6"> EdDSA and Ed25519
 *         draft-josefsson-eddsa-ed25519-02 - section 6 - Test Vectors for Ed25519</A>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class Ed25519VectorsTest<PUB extends PublicKey, PRV extends PrivateKey> extends JUnitTestSupport {
    private byte[] prvBytes;
    private PRV privateKey;
    private byte[] pubBytes;
    private PUB publicKey;
    private byte[] msgBytes;
    private byte[] expSignature;

    public void initEd25519VectorsTest(
            String name, EdDSASupport<PUB, PRV> support, String prvKey, String pubKey, String msg, String signature)
            throws GeneralSecurityException, IOException {
        prvBytes = BufferUtils.decodeHex(BufferUtils.EMPTY_HEX_SEPARATOR, prvKey);
        privateKey = support.generateEDDSAPrivateKey(prvBytes.clone());
        pubBytes = BufferUtils.decodeHex(BufferUtils.EMPTY_HEX_SEPARATOR, pubKey);
        publicKey = support.generateEDDSAPublicKey(pubBytes.clone());
        msgBytes = BufferUtils.decodeHex(BufferUtils.EMPTY_HEX_SEPARATOR, msg);
        expSignature = BufferUtils.decodeHex(BufferUtils.EMPTY_HEX_SEPARATOR, signature);
    }

    public static List<Object[]> parameters() {
        List<Object[]> parameters = new ArrayList<>();
        Map<String, EdDSASupport<?, ?>> supportedSecurityProviders = new LinkedHashMap<>();
        supportedSecurityProviders.put(SecurityUtils.EDDSA, new NetI2pCryptoEdDSASupport());
        supportedSecurityProviders.put(SecurityUtils.BOUNCY_CASTLE, new BouncyCastleEdDSASupport());
        for (Map.Entry<String, EdDSASupport<?, ?>> entry : supportedSecurityProviders.entrySet()) {
            String supportClassName = entry.getValue().getClass().getSimpleName();
            parameters.add(new Object[] {
                    supportClassName + " TEST1 - empty message",
                    entry.getValue(),
                    entry.getKey(),
                    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                    "",
                    "e5564300c360ac729086e2cc806e828a"
                        + "84877f1eb8e5d974d873e06522490155"
                        + "5fb8821590a33bacc61e39701cf9b46b"
                        + "d25bf5f0595bbe24655141438e7a100b"
            });
            parameters.add(new Object[] {
                    supportClassName + " TEST2 - one byte",
                    entry.getValue(),
                    entry.getKey(),
                    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                    "72",
                    "92a009a9f0d4cab8720e820b5f642540"
                          + "a2b27b5416503f8fb3762223ebdb69da"
                          + "085ac1e43e15996e458f3613d0f11d8c"
                          + "387b2eaeb4302aeeb00d291612bb0c00"
            });
            parameters.add(new Object[] {
                    supportClassName + " TEST3 - 2 bytes",
                    entry.getValue(),
                    entry.getKey(),
                    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                    "af82",
                    "6291d657deec24024827e69c3abe01a3"
                            + "0ce548a284743a445e3680d7db5ac3ac"
                            + "18ff9b538d16f290ae67f760984dc659"
                            + "4a7c15e9716ed28dc027beceea1ec40a"
            });
            parameters.add(new Object[] {
                    supportClassName + " TEST1024 - large message",
                    entry.getValue(),
                    entry.getKey(),
                    "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
                    "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
                    "08b8b2b733424243760fe426a4b54908"
                                                                                        + "632110a66c2f6591eabd3345e3e4eb98"
                                                                                        + "fa6e264bf09efe12ee50f8f54e9f77b1"
                                                                                        + "e355f6c50544e23fb1433ddf73be84d8"
                                                                                        + "79de7c0046dc4996d9e773f4bc9efe57"
                                                                                        + "38829adb26c81b37c93a1b270b20329d"
                                                                                        + "658675fc6ea534e0810a4432826bf58c"
                                                                                        + "941efb65d57a338bbd2e26640f89ffbc"
                                                                                        + "1a858efcb8550ee3a5e1998bd177e93a"
                                                                                        + "7363c344fe6b199ee5d02e82d522c4fe"
                                                                                        + "ba15452f80288a821a579116ec6dad2b"
                                                                                        + "3b310da903401aa62100ab5d1a36553e"
                                                                                        + "06203b33890cc9b832f79ef80560ccb9"
                                                                                        + "a39ce767967ed628c6ad573cb116dbef"
                                                                                        + "efd75499da96bd68a8a97b928a8bbc10"
                                                                                        + "3b6621fcde2beca1231d206be6cd9ec7"
                                                                                        + "aff6f6c94fcd7204ed3455c68c83f4a4"
                                                                                        + "1da4af2b74ef5c53f1d8ac70bdcb7ed1"
                                                                                        + "85ce81bd84359d44254d95629e9855a9"
                                                                                        + "4a7c1958d1f8ada5d0532ed8a5aa3fb2"
                                                                                        + "d17ba70eb6248e594e1a2297acbbb39d"
                                                                                        + "502f1a8c6eb6f1ce22b3de1a1f40cc24"
                                                                                        + "554119a831a9aad6079cad88425de6bd"
                                                                                        + "e1a9187ebb6092cf67bf2b13fd65f270"
                                                                                        + "88d78b7e883c8759d2c4f5c65adb7553"
                                                                                        + "878ad575f9fad878e80a0c9ba63bcbcc"
                                                                                        + "2732e69485bbc9c90bfbd62481d9089b"
                                                                                        + "eccf80cfe2df16a2cf65bd92dd597b07"
                                                                                        + "07e0917af48bbb75fed413d238f5555a"
                                                                                        + "7a569d80c3414a8d0859dc65a46128ba"
                                                                                        + "b27af87a71314f318c782b23ebfe808b"
                                                                                        + "82b0ce26401d2e22f04d83d1255dc51a"
                                                                                        + "ddd3b75a2b1ae0784504df543af8969b"
                                                                                        + "e3ea7082ff7fc9888c144da2af58429e"
                                                                                        + "c96031dbcad3dad9af0dcbaaaf268cb8"
                                                                                        + "fcffead94f3c7ca495e056a9b47acdb7"
                                                                                        + "51fb73e666c6c655ade8297297d07ad1"
                                                                                        + "ba5e43f1bca32301651339e22904cc8c"
                                                                                        + "42f58c30c04aafdb038dda0847dd988d"
                                                                                        + "cda6f3bfd15c4b4c4525004aa06eeff8"
                                                                                        + "ca61783aacec57fb3d1f92b0fe2fd1a8"
                                                                                        + "5f6724517b65e614ad6808d6f6ee34df"
                                                                                        + "f7310fdc82aebfd904b01e1dc54b2927"
                                                                                        + "094b2db68d6f903b68401adebf5a7e08"
                                                                                        + "d78ff4ef5d63653a65040cf9bfd4aca7"
                                                                                        + "984a74d37145986780fc0b16ac451649"
                                                                                        + "de6188a7dbdf191f64b5fc5e2ab47b57"
                                                                                        + "f7f7276cd419c17a3ca8e1b939ae49e4"
                                                                                        + "88acba6b965610b5480109c8b17b80e1"
                                                                                        + "b7b750dfc7598d5d5011fd2dcc5600a3"
                                                                                        + "2ef5b52a1ecc820e308aa342721aac09"
                                                                                        + "43bf6686b64b2579376504ccc493d97e"
                                                                                        + "6aed3fb0f9cd71a43dd497f01f17c0e2"
                                                                                        + "cb3797aa2a2f256656168e6c496afc5f"
                                                                                        + "b93246f6b1116398a346f1a641f3b041"
                                                                                        + "e989f7914f90cc2c7fff357876e506b5"
                                                                                        + "0d334ba77c225bc307ba537152f3f161"
                                                                                        + "0e4eafe595f6d9d90d11faa933a15ef1"
                                                                                        + "369546868a7f3a45a96768d40fd9d034"
                                                                                        + "12c091c6315cf4fde7cb68606937380d"
                                                                                        + "b2eaaa707b4c4185c32eddcdd306705e"
                                                                                        + "4dc1ffc872eeee475a64dfac86aba41c"
                                                                                        + "0618983f8741c5ef68d3a101e8a3b8ca"
                                                                                        + "c60c905c15fc910840b94c00a0b9d0",
                    "0aab4c900501b3e24d7cdf4663326a3a"
                                                                                                                            + "87df5e4843b2cbdb67cbf6e460fec350"
                                                                                                                            + "aa5371b1508f9f4528ecea23c436d94b"
                                                                                                                            + "5e8fcd4f681e30a6ac00a9704a188a03"
            });
        }
        return parameters;
    }

    @BeforeAll
    static void checkEDDSASupported() {
        Assumptions.assumeTrue(SecurityUtils.isEDDSACurveSupported(), "EDDSA N/A");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    public void publicKeyBytes(
            String name, EdDSASupport<PUB, PRV> support, String provider, String prvKey, String pubKey, String msg,
            String signature) throws Exception {
        initEd25519VectorsTest(name, support, prvKey, pubKey, msg, signature);
        byte[] publicSeed = support.getPublicKeyData(publicKey);
        assertArrayEquals(pubBytes, publicSeed, "Mismatched public seed value");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    public void privateKeyBytes(
            String name, EdDSASupport<PUB, PRV> support, String provider, String prvKey, String pubKey, String msg,
            String signature) throws Exception {
        initEd25519VectorsTest(name, support, prvKey, pubKey, msg, signature);
        byte[] privateSeed = support.getPrivateKeyData(privateKey);
        assertArrayEquals(prvBytes, privateSeed, "Mismatched private seed value");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    public void signature(
            String name, EdDSASupport<PUB, PRV> support, String provider, String prvKey, String pubKey, String msg,
            String signature) throws Exception {
        initEd25519VectorsTest(name, support, prvKey, pubKey, msg, signature);
        Signature signer = support.getEDDSASigner();
        signer.initSigner(null, privateKey);
        signer.update(null, msgBytes.clone());

        byte[] actSignature = signer.sign(null);
        assertArrayEquals(expSignature, actSignature, "Mismatched signature");

        Signature verifier = support.getEDDSASigner();
        verifier.initVerifier(null, publicKey);
        verifier.update(null, msgBytes.clone());
        assertTrue(verifier.verify(null, expSignature), "Verification failed");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    public void partialBufferSignature(
            String name, EdDSASupport<PUB, PRV> support, String provider, String prvKey, String pubKey, String msg,
            String signature)
            throws Exception {
        initEd25519VectorsTest(name, support, prvKey, pubKey, msg, signature);
        byte[] extraData = getCurrentTestName().getBytes(StandardCharsets.UTF_8);
        byte[] dataBuf = new byte[msgBytes.length + extraData.length];
        int offset = extraData.length / 2;
        System.arraycopy(extraData, 0, dataBuf, 0, offset);
        System.arraycopy(msgBytes, 0, dataBuf, offset, msgBytes.length);
        System.arraycopy(extraData, offset, dataBuf, offset + msgBytes.length, extraData.length - offset);

        Signature signer = support.getEDDSASigner();
        signer.initSigner(null, privateKey);
        signer.update(null, dataBuf.clone(), offset, msgBytes.length);

        byte[] actSignature = signer.sign(null);
        assertArrayEquals(expSignature, actSignature, "Mismatched signature");

        Signature verifier = support.getEDDSASigner();
        verifier.initVerifier(null, publicKey);
        verifier.update(null, dataBuf.clone(), offset, msgBytes.length);
        assertTrue(verifier.verify(null, expSignature), "Verification failed");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    public void recoverEDDSAPublicKey(
            String name, EdDSASupport<PUB, PRV> support, String provider, String prvKey, String pubKey, String msg,
            String signature) throws Exception {
        initEd25519VectorsTest(name, support, prvKey, pubKey, msg, signature);
        PUB recoveredKey = support.recoverEDDSAPublicKey(privateKey);
        assertTrue(support.compareEDDSAPPublicKeys(publicKey, recoveredKey), "Recovered key is not equal");
        byte[] recoveredBytes = support.getPublicKeyData(recoveredKey);
        assertArrayEquals(pubBytes, recoveredBytes, "Mismatched public seed value");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    public void createPublicKeySpec(
            String name, EdDSASupport<PUB, PRV> support, String provider, String prvKey, String pubKey, String msg,
            String signature) throws Exception {
        initEd25519VectorsTest(name, support, prvKey, pubKey, msg, signature);
        KeySpec keySpec = support.createPublicKeySpec(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance(support.getKeyFactoryAlgorithm(), provider);
        PUB generatedKey = (PUB) keyFactory.generatePublic(keySpec);
        assertTrue(support.compareEDDSAPPublicKeys(publicKey, generatedKey), "Generated key is not equal");
        byte[] generatedBytes = support.getPublicKeyData(generatedKey);
        assertArrayEquals(pubBytes, generatedBytes, "Mismatched public seed value");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    public void createPrivateKeySpec(
            String name, EdDSASupport<PUB, PRV> support, String provider, String prvKey, String pubKey, String msg,
            String signature) throws Exception {
        initEd25519VectorsTest(name, support, prvKey, pubKey, msg, signature);
        KeySpec keySpec = support.createPrivateKeySpec(privateKey);
        KeyFactory keyFactory = KeyFactory.getInstance(support.getKeyFactoryAlgorithm(), provider);
        PRV generatedKey = (PRV) keyFactory.generatePrivate(keySpec);
        assertTrue(support.compareEDDSAPrivateKeys(privateKey, generatedKey), "Generated key is not equal");
        byte[] generatedBytes = support.getPrivateKeyData(generatedKey);
        assertArrayEquals(prvBytes, generatedBytes, "Mismatched private seed value");
    }

}
