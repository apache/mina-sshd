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

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

import org.apache.sshd.client.config.keys.ClientIdentity;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class SignatureVariantTestSupport extends JUnitTestSupport {

    protected static KeyPair initializeSigningKeyPair(String algorithm)
            throws IOException, GeneralSecurityException {
        String resourceKey = ClientIdentity.getIdentityFileName(algorithm);
        URL urlKeyPair = SignatureVariantTestSupport.class.getResource(resourceKey);
        assertNotNull(urlKeyPair, "Missing key-pair resource: " + resourceKey);
        try (InputStream stream = urlKeyPair.openStream()) {
            Iterable<KeyPair> ids = SecurityUtils.loadKeyPairIdentities(
                    null, NamedResource.ofName(resourceKey), stream, null);
            return GenericUtils.head(ids);
        }
    }

    public void signature(SignatureFactory factory, KeyPair kp) throws Exception {
        Assumptions.assumeTrue(factory.isSupported(), "Unsupported factory: " + factory);

        byte[] data = (getClass().getName() + "#" + getCurrentTestName())
                .getBytes(StandardCharsets.UTF_8);
        Signature signer = factory.create();
        signer.initSigner(null, kp.getPrivate());
        signer.update(null, data);

        byte[] signature = signer.sign(null);
        Signature verifier = factory.create();
        verifier.initVerifier(null, kp.getPublic());
        verifier.update(null, data);
        verifier.verify(null, signature);
    }

}
