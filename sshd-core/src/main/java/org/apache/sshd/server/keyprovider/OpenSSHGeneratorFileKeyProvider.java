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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.ssl.PEMItem;
import org.apache.commons.ssl.PEMUtil;
import org.apache.commons.ssl.PKCS8Key;

/**
 * Read SSH keys without resorting to BouncyCastle
 */
public class OpenSSHGeneratorFileKeyProvider extends AbstractGeneratorHostKeyProvider {
    private String password;

    public OpenSSHGeneratorFileKeyProvider() {
    }

    public OpenSSHGeneratorFileKeyProvider(String path) {
        setPath(Paths.get(path));
    }

    public OpenSSHGeneratorFileKeyProvider(String path, String algorithm) {
        this(path);
        setAlgorithm(algorithm);
    }

    public OpenSSHGeneratorFileKeyProvider(String path, String algorithm, int keySize) {
        this(path, algorithm);
        setKeySize(keySize);
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    protected KeyPair doReadKeyPair(String resourceKey, InputStream is) throws IOException, GeneralSecurityException {
        PKCS8Key pkcs8 = new PKCS8Key(is, password == null ? null : password.toCharArray());
        return new KeyPair(pkcs8.getPublicKey(), pkcs8.getPrivateKey());
    }

    @Override
    protected void doWriteKeyPair(String resourceKey, KeyPair kp, OutputStream os) throws IOException, GeneralSecurityException {
        Collection<Object> items = new ArrayList<>();
        items.add(new PEMItem(kp.getPrivate().getEncoded(), "PRIVATE KEY"));
        byte[] bytes = PEMUtil.encode(items);
        os.write(bytes);
        os.close();
    }

}
