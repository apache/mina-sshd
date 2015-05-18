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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;

import org.apache.sshd.common.keyprovider.AbstractKeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.SecurityUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractGeneratorHostKeyProvider extends AbstractKeyPairProvider {

    private String path;
    private String algorithm;
    private int keySize;
    private AlgorithmParameterSpec keySpec;
    private KeyPair keyPair;
    private boolean overwriteAllowed = true;

    protected AbstractGeneratorHostKeyProvider() {
        this(null);
    }

    protected AbstractGeneratorHostKeyProvider(String path) {
        this(path, "DSA");
    }

    protected AbstractGeneratorHostKeyProvider(String path, String algorithm) {
        this(path, algorithm, 0);
    }

    protected AbstractGeneratorHostKeyProvider(String path, String algorithm, int keySize) {
        this.path = path;
        this.algorithm = algorithm;
        this.keySize = keySize;
    }

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

    public AlgorithmParameterSpec getKeySpec() {
        return keySpec;
    }

    public void setKeySpec(AlgorithmParameterSpec keySpec) {
        this.keySpec = keySpec;
    }

    public boolean isOverwriteAllowed() {
        return overwriteAllowed;
    }

    public void setOverwriteAllowed(boolean overwriteAllowed) {
        this.overwriteAllowed = overwriteAllowed;
    }

    protected abstract KeyPair doReadKeyPair(InputStream is) throws Exception;

    protected abstract void doWriteKeyPair(KeyPair kp, OutputStream os) throws Exception;

    @Override
    public synchronized Iterable<KeyPair> loadKeys() {
        if (keyPair == null) {
            if (!GenericUtils.isEmpty(path)) {
                File f = new File(path);
                if (f.exists() && f.isFile()) {
                    keyPair = readKeyPair(f);
                }
            }
        }

        if (keyPair == null) {
            keyPair = generateKeyPair(getAlgorithm());
            if ((keyPair != null) && (!GenericUtils.isEmpty(path))) {
                writeKeyPair(keyPair, new File(path));
            }
        }

        if (keyPair == null) {
            return Collections.emptyList();
        }

        return Collections.singleton(keyPair);
    }

    private KeyPair readKeyPair(File f) {
        try(InputStream is = new FileInputStream(f)) {
            return doReadKeyPair(is);
        } catch (Exception e) {
            log.warn("Unable to read key {}: {}", f.getAbsolutePath(), e);
            return null;
        }
    }

    private void writeKeyPair(KeyPair kp, File f) {
        if ((!f.exists()) || isOverwriteAllowed()) {
            try(OutputStream os = new FileOutputStream(f)) {
                doWriteKeyPair(kp, os);
            } catch (Exception e) {
                log.warn("Unable to write key {}: {}", path, e);
            }
        } else {
            log.error("Overwriting key ({}) is disabled: using throwaway {}", f.getAbsolutePath(), kp);
        }
    }

    private KeyPair generateKeyPair(String algorithm) {
        try {
            KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator(algorithm);
            if (keySpec != null) {
                generator.initialize(keySpec);
            } else if (keySize != 0) {
                generator.initialize(keySize);
            }
            log.info("generateKeyPair(" + algorithm + ") generating host key...");
            KeyPair kp = generator.generateKeyPair();
            return kp;
        } catch (Exception e) {
            log.warn("generateKeyPair(" + algorithm + ") Unable to generate keypair", e);
            return null;
        }
    }
}
