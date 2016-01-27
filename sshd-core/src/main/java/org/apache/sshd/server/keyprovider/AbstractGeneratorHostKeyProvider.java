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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.AbstractKeyPairProvider;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.io.IoUtils;

/**
 * Holds a <U>single</U> {@link KeyPair} which is generated the 1st time
 * {@link #loadKeys()} is called. If there is a file backing it up and the
 * file exists, the key is loaded from it. Otherwise a new key pair is
 * generated and saved (provided a path is configured and {@link #isOverwriteAllowed()}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractGeneratorHostKeyProvider extends AbstractKeyPairProvider {
    public static final String DEFAULT_ALGORITHM = "DSA";
    public static final boolean DEFAULT_ALLOWED_TO_OVERWRITE = true;

    private Path path;
    private String algorithm = DEFAULT_ALGORITHM;
    private int keySize;
    private AlgorithmParameterSpec keySpec;
    private KeyPair keyPair;
    private boolean overwriteAllowed = DEFAULT_ALLOWED_TO_OVERWRITE;

    protected AbstractGeneratorHostKeyProvider() {
        super();
    }

    public Path getPath() {
        return path;
    }

    public void setFile(File file) {
        setPath((file == null) ? null : file.toPath());
    }

    public void setPath(Path path) {
        this.path = (path == null) ? null : path.toAbsolutePath();
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

    @Override
    public synchronized Iterable<KeyPair> loadKeys() {
        Path keyPath = getPath();

        if (keyPair == null) {
            if (keyPath != null) {
                LinkOption[] options = IoUtils.getLinkOptions(false);
                if (Files.exists(keyPath, options) && Files.isRegularFile(keyPath, options)) {
                    try {
                        keyPair = readKeyPair(keyPath, IoUtils.EMPTY_OPEN_OPTIONS);
                    } catch (Throwable e) {
                        log.warn("Failed ({}) to load from {}: {}",
                                 e.getClass().getSimpleName(), keyPath, e.getMessage());
                        if (log.isDebugEnabled()) {
                            log.debug("loadKeys(" + keyPath + ") failure details", e);
                        }
                    }
                }
            }
        }

        if (keyPair == null) {
            String alg = getAlgorithm();
            try {
                keyPair = generateKeyPair(alg);
            } catch (Throwable e) {
                log.warn("loadKeys({})[{}] Failed ({}) to generate {} key-pair: {}",
                         keyPath, alg, e.getClass().getSimpleName(), alg, e.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("loadKeys(" + keyPath + ")[" + alg + "] key-pair generation failure details", e);
                }
            }

            if ((keyPair != null) && (keyPath != null)) {
                try {
                    writeKeyPair(keyPair, keyPath);
                } catch (Throwable e) {
                    log.warn("loadKeys({})[{}] Failed ({}) to write {} key: {}",
                             alg, keyPath, e.getClass().getSimpleName(), alg, e.getMessage());
                    if (log.isDebugEnabled()) {
                        log.debug("loadKeys(" + keyPath + ")[" + alg + "] writefailure details", e);
                    }
                }
            }
        }

        if (keyPair == null) {
            return Collections.emptyList();
        } else {
            return Collections.singleton(keyPair);
        }
    }

    protected KeyPair readKeyPair(Path keyPath, OpenOption... options) throws IOException, GeneralSecurityException {
        try (InputStream inputStream = Files.newInputStream(keyPath, options)) {
            return doReadKeyPair(keyPath.toString(), inputStream);
        }
    }

    protected abstract KeyPair doReadKeyPair(String resourceKey, InputStream inputStream) throws IOException, GeneralSecurityException;

    protected void writeKeyPair(KeyPair kp, Path keyPath, OpenOption... options) throws IOException, GeneralSecurityException {
        if ((!Files.exists(keyPath)) || isOverwriteAllowed()) {
            try (OutputStream os = Files.newOutputStream(keyPath, options)) {
                doWriteKeyPair(keyPath.toString(), kp, os);
            } catch (Throwable e) {
                log.warn("writeKeyPair({}) failed ({}) to write key {}: {}",
                         keyPath, e.getClass().getSimpleName(), e.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("writeKeyPair(" + keyPath + ") write failure details", e);
                }
            }
        } else {
            log.error("Overwriting key ({}) is disabled: using throwaway {}: {}",
                      keyPath, KeyUtils.getKeyType(kp), KeyUtils.getFingerPrint((kp == null) ? null : kp.getPublic()));
        }
    }

    protected abstract void doWriteKeyPair(String resourceKey, KeyPair kp, OutputStream outputStream) throws IOException, GeneralSecurityException;


    protected KeyPair generateKeyPair(String algorithm) throws GeneralSecurityException {
        KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator(algorithm);
        if (keySpec != null) {
            generator.initialize(keySpec);
            log.info("generateKeyPair(" + algorithm + ") generating host key - spec=" + keySpec.getClass().getSimpleName());
        } else if (keySize != 0) {
            generator.initialize(keySize);
            log.info("generateKeyPair(" + algorithm + ") generating host key - size=" + keySize);
        }

        return generator.generateKeyPair();
    }
}
