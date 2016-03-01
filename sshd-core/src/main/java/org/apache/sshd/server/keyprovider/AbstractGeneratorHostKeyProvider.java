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
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

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
    public static final String DEFAULT_ALGORITHM = KeyUtils.DSS_ALGORITHM;
    public static final boolean DEFAULT_ALLOWED_TO_OVERWRITE = true;

    private final AtomicReference<KeyPair> keyPairHolder = new AtomicReference<>();

    private Path path;
    private String algorithm = DEFAULT_ALGORITHM;
    private int keySize;
    private AlgorithmParameterSpec keySpec;
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

    public void clearLoadedKeys() {
        KeyPair kp;
        synchronized (keyPairHolder) {
            kp = keyPairHolder.getAndSet(null);
        }

        if ((kp != null) & log.isDebugEnabled()) {
            PublicKey key = kp.getPublic();
            log.debug("clearLoadedKeys({}) removed key={}-{}",
                      getPath(), KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
        }
    }

    @Override   // co-variant return
    public synchronized List<KeyPair> loadKeys() {
        Path keyPath = getPath();
        KeyPair kp;
        synchronized (keyPairHolder) {
            kp = keyPairHolder.get();
            if (kp == null) {
                try {
                    kp = resolveKeyPair(keyPath);
                    if (kp != null) {
                        keyPairHolder.set(kp);
                    }
                } catch (Throwable t) {
                    log.warn("loadKeys({}) Failed ({}) to resolve: {}",
                            keyPath, t.getClass().getSimpleName(), t.getMessage());
                    if (log.isDebugEnabled()) {
                        log.debug("loadKeys(" + keyPath + ") resolution failure details", t);
                    }
                }
            }
        }

        if (kp == null) {
            return Collections.emptyList();
        } else {
            return Collections.singletonList(kp);
        }
    }

    protected KeyPair resolveKeyPair(Path keyPath) throws IOException, GeneralSecurityException {
        if (keyPath != null) {
            LinkOption[] options = IoUtils.getLinkOptions(false);
            if (Files.exists(keyPath, options) && Files.isRegularFile(keyPath, options)) {
                try {
                    KeyPair kp = readKeyPair(keyPath, IoUtils.EMPTY_OPEN_OPTIONS);
                    if (kp != null) {
                        if (log.isDebugEnabled()) {
                            PublicKey key = kp.getPublic();
                            log.debug("resolveKeyPair({}) loaded key={}-{}",
                                      keyPath, KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
                        }
                        return kp;
                    }
                } catch (Throwable e) {
                    log.warn("resolveKeyPair({}) Failed ({}) to load: {}",
                            keyPath, e.getClass().getSimpleName(), e.getMessage());
                    if (log.isDebugEnabled()) {
                        log.debug("resolveKeyPair(" + keyPath + ") load failure details", e);
                    }
                }
            }
        }

        // either no file specified or no key in file
        String alg = getAlgorithm();
        KeyPair kp;
        try {
            kp = generateKeyPair(alg);
            if (kp == null) {
                return null;
            }

            if (log.isDebugEnabled()) {
                PublicKey key = kp.getPublic();
                log.debug("resolveKeyPair({}) generated {} key={}-{}",
                          keyPath, alg, KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
            }
        } catch (Throwable e) {
            log.warn("resolveKeyPair({})[{}] Failed ({}) to generate {} key-pair: {}",
                     keyPath, alg, e.getClass().getSimpleName(), alg, e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("resolveKeyPair(" + keyPath + ")[" + alg + "] key-pair generation failure details", e);
            }

            return null;
        }

        if (keyPath != null) {
            try {
                writeKeyPair(kp, keyPath);
            } catch (Throwable e) {
                log.warn("resolveKeyPair({})[{}] Failed ({}) to write {} key: {}",
                         alg, keyPath, e.getClass().getSimpleName(), alg, e.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("resolveKeyPair(" + keyPath + ")[" + alg + "] write failure details", e);
                }
            }
        }

        return kp;
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
