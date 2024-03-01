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
package org.apache.sshd.server.keyprovider;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import org.junit.Assert;
import org.junit.Test;

public class OpenSSHGeneratorKeyFileProviderTest {
    
    public OpenSSHGeneratorKeyFileProviderTest() {
    }

    @Test
    public void readSshKey() throws Exception {
        OpenSSHGeneratorFileKeyProvider prov = new OpenSSHGeneratorFileKeyProvider("src/test/resources/org/apache/karaf/shell/ssh/test.pem");
        prov.setOverwriteAllowed(false);
        KeyPair keys = prov.loadKeys().iterator().next();
        // how would we tell if they read 'correctly'? Well, the base class will throw if the key isn't reasonable.
        Assert.assertNotNull(keys);
        Assert.assertTrue("Loaded key is not RSA Key", keys.getPublic() instanceof RSAPublicKey);
        Assert.assertEquals(65537, ((RSAPublicKey) keys.getPublic()).getPublicExponent().intValue());
    }
    
    @Test
    public void writeSshKey() throws Exception {
        // create a temporary file
        File temp = File.createTempFile(this.getClass().getCanonicalName(), ".pem");
        temp.deleteOnExit();
        OpenSSHGeneratorFileKeyProvider prov = new OpenSSHGeneratorFileKeyProvider(temp.getPath(), "RSA",
                                                                                   4096);
        KeyPair keys = prov.loadKeys().iterator().next();
        Assert.assertNotNull(keys);
        Assert.assertTrue(temp.exists());
        Assert.assertFalse(temp.length() == 0);
        BigInteger privateExponent = ((RSAPrivateCrtKey)keys.getPrivate()).getPrivateExponent();
        // read and check if correctly read
        prov = new OpenSSHGeneratorFileKeyProvider(temp.getPath());
        keys = prov.loadKeys().iterator().next();
        Assert.assertNotNull(keys);
        Assert.assertTrue("Loaded key is not RSA Key", keys.getPrivate() instanceof RSAPrivateCrtKey);
        BigInteger privateExponent2 = ((RSAPrivateCrtKey)keys.getPrivate()).getPrivateExponent();
        Assert.assertEquals(privateExponent, privateExponent2);
    }
}
