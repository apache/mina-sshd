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
package org.apache.sshd.common.keyprovider;

import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.common.util.SecurityUtils;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This host key provider loads private keys from the specified files.
 * 
 * Note that this class has a direct dependency on BouncyCastle and won't work
 * unless it has been correctly registered as a security provider.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class FileKeyPairProvider extends AbstractKeyPairProvider {

    private static final Logger LOG = LoggerFactory.getLogger(FileKeyPairProvider.class);

    private String[] files;
    private PasswordFinder passwordFinder;

    public FileKeyPairProvider() {
    }

    public FileKeyPairProvider(String[] files) {
        this.files = files;
    }

    public FileKeyPairProvider(String[] files, PasswordFinder passwordFinder) {
        this.files = files;
        this.passwordFinder = passwordFinder;
    }

    public String[] getFiles() {
        return files;
    }

    public void setFiles(String[] files) {
        this.files = files;
    }

    public PasswordFinder getPasswordFinder() {
        return passwordFinder;
    }

    public void setPasswordFinder(PasswordFinder passwordFinder) {
        this.passwordFinder = passwordFinder;
    }

    protected KeyPair[] loadKeys() {
        if (!SecurityUtils.isBouncyCastleRegistered()) {
            throw new IllegalStateException("BouncyCastle must be registered as a JCE provider");
        }
        List<KeyPair> keys = new ArrayList<KeyPair>();
        for (int i = 0; i < files.length; i++) {
            try {
                PEMReader r = new PEMReader(new InputStreamReader(new FileInputStream(files[i])), passwordFinder);
                try {
                    Object o = r.readObject();
                    if (o instanceof KeyPair) {
                        keys.add((KeyPair) o);
                    }
                } finally {
                    r.close();
                }
            } catch (Exception e) {
                LOG.info("Unable to read key {}: {}", files[i], e);
            }
        }
        return keys.toArray(new KeyPair[keys.size()]);
    }

}
