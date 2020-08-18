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
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.AlgorithmNameProvider;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.BuiltinIdentities;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.AbstractKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeySizeIndicator;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * Holds a <U>single</U> {@link KeyPair} which is generated the 1st time {@link #loadKeys(SessionContext)} is called. If
 * there is a file backing it up and the file exists, the key is loaded from it. Otherwise a new key pair is generated
 * and saved (provided a path is configured and {@link #isOverwriteAllowed()}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractGeneratorHostKeyProvider
        extends AbstractKeyPairProvider
        implements AlgorithmNameProvider, KeySizeIndicator {
    public static final String DEFAULT_ALGORITHM = KeyUtils.EC_ALGORITHM;
    public static final boolean DEFAULT_ALLOWED_TO_OVERWRITE = true;

    private final AtomicReference<Iterable<KeyPair>> keyPairHolder = new AtomicReference<>();

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

    public void setPath(Path path) {
        this.path = (path == null) ? null : path.toAbsolutePath();
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
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
        Iterable<KeyPair> ids;
        synchronized (keyPairHolder) {
            ids = keyPairHolder.getAndSet(null);
        }

        if ((ids != null) & log.isDebugEnabled()) {
            log.debug("clearLoadedKeys({}) removed keys", getPath());
        }
    }

    @Override // co-variant return
    public synchronized List<KeyPair> loadKeys(SessionContext session) {
        Path keyPath = getPath();
        Iterable<KeyPair> ids;
        synchronized (keyPairHolder) {
            ids = keyPairHolder.get();
            if (ids == null) {
                try {
                    ids = resolveKeyPairs(session, keyPath);
                    if (ids != null) {
                        keyPairHolder.set(ids);
                    }
                } catch (Throwable t) {
                    warn("loadKeys({}) Failed ({}) to resolve: {}",
                            keyPath, t.getClass().getSimpleName(), t.getMessage(), t);
                }
            }
        }

        List<KeyPair> pairs = Collections.emptyList();
        if (ids instanceof List<?>) {
            pairs = (List<KeyPair>) ids;
        } else if (ids != null) {
            pairs = new ArrayList<>();
            for (KeyPair kp : ids) {
                if (kp == null) {
                    continue;
                }

                pairs.add(kp);
            }
        }

        return pairs;
    }

    protected Iterable<KeyPair> resolveKeyPairs(SessionContext session, Path keyPath)
            throws IOException, GeneralSecurityException {
        String alg = getAlgorithm();
        if (keyPath != null) {
            try {
                Iterable<KeyPair> ids = loadFromFile(session, alg, keyPath);
                KeyPair kp = GenericUtils.head(ids);
                if (kp != null) {
                    return ids;
                }
            } catch (Throwable e) {
                warn("resolveKeyPair({}) Failed ({}) to load: {}",
                        keyPath, e.getClass().getSimpleName(), e.getMessage(), e);
            }
        }

        // either no file specified or no key in file
        KeyPair kp = null;
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
            warn("resolveKeyPair({})[{}] Failed ({}) to generate {} key-pair: {}",
                    keyPath, alg, e.getClass().getSimpleName(), alg, e.getMessage(), e);
            return null;
        }

        if (keyPath != null) {
            try {
                writeKeyPair(kp, keyPath);
            } catch (Throwable e) {
                warn("resolveKeyPair({})[{}] Failed ({}) to write {} key: {}",
                        alg, keyPath, e.getClass().getSimpleName(), alg, e.getMessage(), e);
            }
        }

        return Collections.singletonList(kp);
    }

    protected Iterable<KeyPair> loadFromFile(SessionContext session, String alg, Path keyPath)
            throws IOException, GeneralSecurityException {
        LinkOption[] options = IoUtils.getLinkOptions(true);
        if ((!Files.exists(keyPath, options)) || (!Files.isRegularFile(keyPath, options))) {
            return null;
        }

        Iterable<KeyPair> ids = readKeyPairs(session, keyPath, IoUtils.EMPTY_OPEN_OPTIONS);
        KeyPair kp = GenericUtils.head(ids);
        if (kp == null) {
            return null;
        }

        // Assume all keys are of same type
        PublicKey key = kp.getPublic();
        String keyAlgorithm = key.getAlgorithm();
        if (BuiltinIdentities.Constants.ECDSA.equalsIgnoreCase(keyAlgorithm)) {
            keyAlgorithm = KeyUtils.EC_ALGORITHM;
        } else if (BuiltinIdentities.Constants.ED25519.equalsIgnoreCase(keyAlgorithm)) {
            keyAlgorithm = SecurityUtils.EDDSA;
        }

        if (Objects.equals(alg, keyAlgorithm)) {
            if (log.isDebugEnabled()) {
                log.debug("resolveKeyPair({}) loaded key={}-{}",
                        keyPath, KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
            }
            return ids;
        }

        // Not same algorithm - start again
        if (log.isDebugEnabled()) {
            log.debug("resolveKeyPair({}) mismatched loaded key algorithm: expected={}, loaded={}",
                    keyPath, alg, keyAlgorithm);
        }
        Files.deleteIfExists(keyPath);
        return null;
    }

    protected Iterable<KeyPair> readKeyPairs(SessionContext session, Path keyPath, OpenOption... options)
            throws IOException, GeneralSecurityException {
        PathResource location = new PathResource(keyPath, options);
        try (InputStream inputStream = location.openInputStream()) {
            return doReadKeyPairs(session, location, inputStream);
        }
    }

    protected Iterable<KeyPair> doReadKeyPairs(SessionContext session, NamedResource resourceKey, InputStream inputStream)
            throws IOException, GeneralSecurityException {
        return SecurityUtils.loadKeyPairIdentities(session, resourceKey, inputStream, null);
    }

    protected void writeKeyPair(KeyPair kp, Path keyPath, OpenOption... options)
            throws IOException, GeneralSecurityException {
        if ((!Files.exists(keyPath)) || isOverwriteAllowed()) {
            PathResource location = new PathResource(keyPath); // The options are for write (!!)
            try (OutputStream os = Files.newOutputStream(keyPath, options)) {
                doWriteKeyPair(location, kp, os);
            } catch (Throwable e) {
                warn("writeKeyPair({}) failed ({}) to write key {}: {}",
                        keyPath, e.getClass().getSimpleName(), kp, e.getMessage(), e);
            }
        } else {
            log.error("Overwriting key ({}) is disabled: using throwaway {}: {}",
                    keyPath, KeyUtils.getKeyType(kp), KeyUtils.getFingerPrint((kp == null) ? null : kp.getPublic()));
        }
    }

    protected abstract void doWriteKeyPair(
            NamedResource resourceKey, KeyPair kp, OutputStream outputStream)
            throws IOException, GeneralSecurityException;

    protected KeyPair generateKeyPair(String algorithm) throws GeneralSecurityException {
        KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator(algorithm);
        if (keySpec != null) {
            generator.initialize(keySpec);
            log.info("generateKeyPair(" + algorithm + ") generating host key - spec=" + keySpec.getClass().getSimpleName());
        } else if (KeyUtils.EC_ALGORITHM.equals(algorithm)) {
            ECCurves curve;
            // If left to our own devices choose the biggest key size possible
            if (keySize == 0) {
                int numCurves = ECCurves.SORTED_KEY_SIZE.size();
                curve = ECCurves.SORTED_KEY_SIZE.get(numCurves - 1);
            } else {
                curve = ECCurves.fromCurveSize(keySize);
                if (curve == null) {
                    throw new InvalidKeyException("No match found for curve with key size=" + keySize);
                }
            }
            generator.initialize(curve.getParameters());
            log.info("generateKeyPair(" + algorithm + ") generating host key=" + curve);
        } else if (keySize != 0) {
            generator.initialize(keySize);
            log.info("generateKeyPair(" + algorithm + ") generating host key - size=" + keySize);
        }

        return generator.generateKeyPair();
    }
}
