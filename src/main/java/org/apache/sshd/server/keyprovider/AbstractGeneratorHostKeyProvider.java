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

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.apache.sshd.common.keyprovider.AbstractKeyPairProvider;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.util.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractGeneratorHostKeyProvider extends AbstractKeyPairProvider {

    private static final Logger LOG = LoggerFactory.getLogger(FileKeyPairProvider.class);

    private String path;
    private String algorithm = "DSA";
    private int keySize;
    private KeyPair keyPair;

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    protected abstract KeyPair doReadKeyPair(InputStream is) throws Exception;

    protected abstract void doWriteKeyPair(KeyPair kp, OutputStream os) throws Exception;

    public synchronized KeyPair[] loadKeys() {
        if (keyPair == null) {
            if (path != null) {
                File f = new File(path);
                if (f.exists() && f.isFile()) {
                    keyPair = readKeyPair(f);
                }
            }
            if (keyPair == null) {
                keyPair = generateKeyPair(algorithm);
                if (keyPair != null && path != null) {
                    writeKeyPair(keyPair, new File(path));
                }
            }
            if (keyPair == null) {
                return new KeyPair[0];
            }
        }
        return new KeyPair[] { keyPair };
    }

    private KeyPair readKeyPair(File f) {
        InputStream is = null;
        try {
            is = new FileInputStream(f);
            return doReadKeyPair(is);
        } catch (Exception e) {
            LOG.info("Unable to read key {}: {}", path, e);
        } finally {
            close(is);
        }
        return null;
    }

    private void writeKeyPair(KeyPair kp, File f) {
        OutputStream os = null;
        try {
            os = new FileOutputStream(f);
            doWriteKeyPair(kp, os);
        } catch (Exception e) {
            LOG.info("Unable to write key {}: {}", path, e);
        } finally {
            close(os);
        }
    }

    private KeyPair generateKeyPair(String algorithm) {
        try {
            KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator(algorithm);
            if (keySize != 0) {
                generator.initialize(keySize);
            }
            LOG.info("Generating host key...");
            KeyPair kp = generator.generateKeyPair();
            return kp;
        } catch (Exception e) {
            LOG.error("Unable to generate keypair", e);
            return null;
        }
    }

    private void close(Closeable c) {
        try {
            if (c != null) {
                c.close();
            }
        } catch (IOException e) {
            // Ignore
        }
    }
}