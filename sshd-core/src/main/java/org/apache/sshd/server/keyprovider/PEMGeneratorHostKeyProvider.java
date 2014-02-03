/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.server.keyprovider;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.KeyPair;

import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PEMGeneratorHostKeyProvider extends AbstractGeneratorHostKeyProvider {

    public PEMGeneratorHostKeyProvider() {
    }

    public PEMGeneratorHostKeyProvider(String path) {
        super(path);
    }

    public PEMGeneratorHostKeyProvider(String path, String algorithm) {
        super(path, algorithm);
    }

    public PEMGeneratorHostKeyProvider(String path, String algorithm, int keySize) {
        super(path, algorithm, keySize);
    }

    protected KeyPair doReadKeyPair(InputStream is) throws Exception {
        PEMParser r = new PEMParser(new InputStreamReader(is));
        Object o = r.readObject();
        JcaPEMKeyConverter pemConverter = new JcaPEMKeyConverter();
        pemConverter.setProvider("BC");
        if (o instanceof PEMKeyPair) {
            o = pemConverter.getKeyPair((PEMKeyPair)o);
            return (KeyPair) o;
        } else if (o instanceof KeyPair) {
            return (KeyPair) o;
        }
        return null;
    }

    protected void doWriteKeyPair(KeyPair kp, OutputStream os) throws Exception {
        PEMWriter w = new PEMWriter(new OutputStreamWriter(os));
        w.writeObject(kp);
        w.flush();
    }

}
