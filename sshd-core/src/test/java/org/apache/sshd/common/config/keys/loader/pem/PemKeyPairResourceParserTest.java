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
package org.apache.sshd.common.config.keys.loader.pem;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.ssl.PEMItem;
import org.apache.commons.ssl.PEMUtil;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.junit.Assert;
import org.junit.Test;

public class PemKeyPairResourceParserTest {
    public PemKeyPairResourceParserTest() {
    }

    @Test
    public void testPkcs8() throws Exception {
        String algorithm = "RSA";
        int keySize = 512;
        KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator(algorithm);
        generator.initialize(keySize);
        KeyPair kp = generator.generateKeyPair();

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        Collection<Object> items = new ArrayList<>();
        items.add(new PEMItem(kp.getPrivate().getEncoded(), "PRIVATE KEY"));
        byte[] bytes = PEMUtil.encode(items);
        os.write(bytes);
        os.close();

        KeyPair kp2 = SecurityUtils.loadKeyPairIdentity("the-key", new ByteArrayInputStream(os.toByteArray()), null);

        Assert.assertEquals(kp.getPublic(), kp2.getPublic());
        Assert.assertEquals(kp.getPrivate(), kp2.getPrivate());
    }
}
