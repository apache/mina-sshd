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

package org.apache.sshd.util.test;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.CodeSource;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.ProtectionDomain;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyPairProviderHolder;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class CommonTestSupportUtils {
    /**
     * URL/URI scheme that refers to a file
     */
    public static final String FILE_URL_SCHEME = "file";
    /**
     * Prefix used in URL(s) that reference a file resource
     */
    public static final String FILE_URL_PREFIX = FILE_URL_SCHEME + ":";

    /**
     * Separator used in URL(s) that reference a resource inside a JAR to denote the sub-path inside the JAR
     */
    public static final char RESOURCE_SUBPATH_SEPARATOR = '!';

    /**
     * Suffix of JAR files
     */
    public static final String JAR_FILE_SUFFIX = ".jar";

    /**
     * URL/URI scheme that refers to a JAR
     */
    public static final String JAR_URL_SCHEME = "jar";

    /**
     * Prefix used in URL(s) that reference a resource inside a JAR
     */
    public static final String JAR_URL_PREFIX = JAR_URL_SCHEME + ":";

    /**
     * Suffix of compile Java class files
     */
    public static final String CLASS_FILE_SUFFIX = ".class";

    public static final List<String> TARGET_FOLDER_NAMES = // NOTE: order is important
            Collections.unmodifiableList(
                    Arrays.asList(
                            "target" /* Maven */,
                            "build" /* Gradle */));

    public static final String DEFAULT_TEST_HOST_KEY_PROVIDER_ALGORITHM = KeyUtils.EC_ALGORITHM;
    public static final int DEFAULT_TEST_HOST_KEY_SIZE = 256;
    public static final String DEFAULT_TEST_HOST_KEY_TYPE = ECCurves.fromCurveSize(DEFAULT_TEST_HOST_KEY_SIZE).getKeyType();

    // uses a cached instance to avoid re-creating the keys as it is a time-consuming effort
    private static final AtomicReference<KeyPairProvider> KEYPAIR_PROVIDER_HOLDER = new AtomicReference<>();
    // uses a cached instance to avoid re-creating the keys as it is a time-consuming effort
    private static final Map<String, FileKeyPairProvider> PROVIDERS_MAP = new ConcurrentHashMap<>();

    private CommonTestSupportUtils() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    /**
     * @param  clazz              A {@link Class} object
     * @return                    A {@link URI} to the location of the class bytes container - e.g., the root folder,
     *                            the containing JAR, etc.. Returns {@code null} if location could not be resolved
     * @throws URISyntaxException if location is not a valid URI
     * @see                       #getClassContainerLocationURL(Class)
     */
    public static URI getClassContainerLocationURI(Class<?> clazz) throws URISyntaxException {
        URL url = getClassContainerLocationURL(clazz);
        return (url == null) ? null : url.toURI();
    }

    /**
     * @param  clazz A {@link Class} object
     * @return       A {@link URL} to the location of the class bytes container - e.g., the root folder, the containing
     *               JAR, etc.. Returns {@code null} if location could not be resolved
     */
    public static URL getClassContainerLocationURL(Class<?> clazz) {
        ProtectionDomain pd = clazz.getProtectionDomain();
        CodeSource cs = (pd == null) ? null : pd.getCodeSource();
        URL url = (cs == null) ? null : cs.getLocation();
        if (url == null) {
            url = getClassBytesURL(clazz);
            if (url == null) {
                return null;
            }

            String srcForm = getURLSource(url);
            if (GenericUtils.isEmpty(srcForm)) {
                return null;
            }

            try {
                url = new URL(srcForm);
            } catch (MalformedURLException e) {
                throw new IllegalArgumentException(
                        "getClassContainerLocationURL(" + clazz.getName() + ")"
                                                   + " Failed to create URL=" + srcForm + " from " + url.toExternalForm()
                                                   + ": " + e.getMessage());
            }
        }

        return url;
    }

    /**
     * @param  uri The {@link URI} value - ignored if {@code null}
     * @return     The URI(s) source path where {@link #JAR_URL_PREFIX} and any sub-resource are stripped
     * @see        #getURLSource(String)
     */
    public static String getURLSource(URI uri) {
        return getURLSource((uri == null) ? null : uri.toString());
    }

    /**
     * @param  url The {@link URL} value - ignored if {@code null}
     * @return     The URL(s) source path where {@link #JAR_URL_PREFIX} and any sub-resource are stripped
     * @see        #getURLSource(String)
     */
    public static String getURLSource(URL url) {
        return getURLSource((url == null) ? null : url.toExternalForm());
    }

    /**
     * @param  externalForm The {@link URL#toExternalForm()} string - ignored if {@code null}/empty
     * @return              The URL(s) source path where {@link #JAR_URL_PREFIX} and any sub-resource are stripped
     */
    public static String getURLSource(String externalForm) {
        String url = externalForm;
        if (GenericUtils.isEmpty(url)) {
            return url;
        }

        url = stripJarURLPrefix(externalForm);
        if (GenericUtils.isEmpty(url)) {
            return url;
        }

        int sepPos = url.indexOf(RESOURCE_SUBPATH_SEPARATOR);
        if (sepPos < 0) {
            return adjustURLPathValue(url);
        } else {
            return adjustURLPathValue(url.substring(0, sepPos));
        }
    }

    /**
     * @param  url A {@link URL} - ignored if {@code null}
     * @return     The path after stripping any trailing '/' provided the path is not '/' itself
     * @see        #adjustURLPathValue(String)
     */
    public static String adjustURLPathValue(URL url) {
        return adjustURLPathValue((url == null) ? null : url.getPath());
    }

    /**
     * @param  path A URL path value - ignored if {@code null}/empty
     * @return      The path after stripping any trailing '/' provided the path is not '/' itself
     */
    public static String adjustURLPathValue(final String path) {
        final int pathLen = (path == null) ? 0 : path.length();
        if ((pathLen <= 1) || (path.charAt(pathLen - 1) != '/')) {
            return path;
        }

        return path.substring(0, pathLen - 1);
    }

    public static String stripJarURLPrefix(String externalForm) {
        String url = externalForm;
        if (GenericUtils.isEmpty(url)) {
            return url;
        }

        if (url.startsWith(JAR_URL_PREFIX)) {
            return url.substring(JAR_URL_PREFIX.length());
        }

        return url;
    }

    /**
     * @param  clazz The request {@link Class}
     * @return       A {@link URL} to the location of the <code>.class</code> file - {@code null} if location could not
     *               be resolved
     */
    public static URL getClassBytesURL(Class<?> clazz) {
        String className = clazz.getName();
        int sepPos = className.indexOf('$');
        // if this is an internal class, then need to use its parent as well
        if (sepPos > 0) {
            sepPos = className.lastIndexOf('.');
            if (sepPos > 0) {
                className = className.substring(sepPos + 1);
            }
        } else {
            className = clazz.getSimpleName();
        }

        return clazz.getResource(className + CLASS_FILE_SUFFIX);
    }

    public static String getClassBytesResourceName(Class<?> clazz) {
        return getClassBytesResourceName((clazz == null) ? null : clazz.getName());
    }

    /**
     * @param  name The fully qualified class name - ignored if {@code null}/empty
     * @return      The relative path of the class file byte-code resource
     */
    public static String getClassBytesResourceName(String name) {
        if (GenericUtils.isEmpty(name)) {
            return name;
        } else {
            return name.replace('.', '/') + CLASS_FILE_SUFFIX;
        }
    }

    public static Path resolve(Path root, String... children) {
        if (GenericUtils.isEmpty(children)) {
            return root;
        } else {
            return resolve(root, Arrays.asList(children));
        }
    }

    public static Path resolve(Path root, Collection<String> children) {
        Path path = root;
        if (!GenericUtils.isEmpty(children)) {
            for (String child : children) {
                path = path.resolve(child);
            }
        }

        return path;
    }

    /**
     * @param  anchor An anchor {@link Class} whose container we want to use as the starting point for the
     *                &quot;target&quot; folder lookup up the hierarchy
     * @return        The &quot;target&quot; <U>folder</U> - {@code null} if not found
     * @see           #detectTargetFolder(Path)
     */
    public static Path detectTargetFolder(Class<?> anchor) {
        Path path = detectTargetFolder(getClassContainerLocationPath(anchor));
        if (path == null) {
            String basedir = System.getProperty("basedir");
            path = detectTargetFolder(Paths.get(basedir, "target"));
        }
        return path;
    }

    /**
     * @param  clazz                    A {@link Class} object
     * @return                          A {@link Path} of the location of the class bytes container - e.g., the root
     *                                  folder, the containing JAR, etc.. Returns {@code null} if location could not be
     *                                  resolved
     * @throws IllegalArgumentException If location is not a valid {@link Path} location
     * @see                             #getClassContainerLocationURI(Class)
     * @see                             #toPathSource(URI)
     */
    public static Path getClassContainerLocationPath(Class<?> clazz)
            throws IllegalArgumentException {
        try {
            URI uri = getClassContainerLocationURI(clazz);
            return toPathSource(uri);
        } catch (URISyntaxException | MalformedURLException e) {
            throw new IllegalArgumentException(e.getClass().getSimpleName() + ": " + e.getMessage(), e);
        }
    }

    /**
     * Converts a {@link URL} that may refer to an internal resource to a {@link Path} representing is
     * &quot;source&quot; container (e.g., if it is a resource in a JAR, then the result is the JAR's path)
     *
     * @param  url                   The {@link URL} - ignored if {@code null}
     * @return                       The matching {@link Path}
     * @throws MalformedURLException If source URL does not refer to a file location
     * @see                          #toPathSource(URI)
     */
    public static Path toPathSource(URL url) throws MalformedURLException {
        if (url == null) {
            return null;
        }

        try {
            return toPathSource(url.toURI());
        } catch (URISyntaxException e) {
            throw new MalformedURLException(
                    "toFileSource(" + url.toExternalForm() + ")"
                                            + " cannot (" + e.getClass().getSimpleName() + ")"
                                            + " convert to URI: " + e.getMessage());
        }
    }

    /**
     * Converts a {@link URI} that may refer to an internal resource to a {@link Path} representing is
     * &quot;source&quot; container (e.g., if it is a resource in a JAR, then the result is the JAR's path)
     *
     * @param  uri                   The {@link URI} - ignored if {@code null}
     * @return                       The matching {@link Path}
     * @throws MalformedURLException If source URI does not refer to a file location
     * @see                          #getURLSource(URI)
     */
    public static Path toPathSource(URI uri) throws MalformedURLException {
        String src = getURLSource(uri);
        if (GenericUtils.isEmpty(src)) {
            return null;
        }

        if (!src.startsWith(FILE_URL_PREFIX)) {
            throw new MalformedURLException("toFileSource(" + src + ") not a '" + FILE_URL_SCHEME + "' scheme");
        }

        try {
            return Paths.get(new URI(src));
        } catch (URISyntaxException e) {
            throw new MalformedURLException(
                    "toFileSource(" + src + ")"
                                            + " cannot (" + e.getClass().getSimpleName() + ")"
                                            + " convert to URI: " + e.getMessage());
        }
    }

    /**
     * @param  anchorFile An anchor {@link Path} we want to use as the starting point for the &quot;target&quot; or
     *                    &quot;build&quot; folder lookup up the hierarchy
     * @return            The &quot;target&quot; <U>folder</U> - {@code null} if not found
     */
    public static Path detectTargetFolder(Path anchorFile) {
        for (Path file = anchorFile; file != null; file = file.getParent()) {
            if (!Files.isDirectory(file)) {
                continue;
            }

            String name = Objects.toString(file.getFileName(), "");
            if (TARGET_FOLDER_NAMES.contains(name)) {
                return file;
            }
        }

        return null;
    }

    public static KeyPair generateKeyPair(String algorithm, int keySize) throws GeneralSecurityException {
        KeyPairGenerator gen = SecurityUtils.getKeyPairGenerator(algorithm);
        if (KeyUtils.EC_ALGORITHM.equalsIgnoreCase(algorithm)) {
            ECCurves curve = ECCurves.fromCurveSize(keySize);
            if (curve == null) {
                throw new InvalidKeySpecException("Unknown curve for key size=" + keySize);
            }
            gen.initialize(curve.getParameters());
        } else {
            gen.initialize(keySize);
        }

        return gen.generateKeyPair();
    }

    public static KeyPairProvider createTestHostKeyProvider(Class<?> anchor) {
        KeyPairProvider provider = KEYPAIR_PROVIDER_HOLDER.get();
        if (provider != null) {
            return provider;
        }

        Path targetFolder
                = Objects.requireNonNull(CommonTestSupportUtils.detectTargetFolder(anchor), "Failed to detect target folder");
        Path file = targetFolder.resolve("hostkey." + DEFAULT_TEST_HOST_KEY_PROVIDER_ALGORITHM.toLowerCase());
        provider = createTestHostKeyProvider(file);

        KeyPairProvider prev = KEYPAIR_PROVIDER_HOLDER.getAndSet(provider);
        if (prev != null) { // check if somebody else beat us to it
            return prev;
        } else {
            return provider;
        }
    }

    public static KeyPairProvider createTestHostKeyProvider(Path path) {
        SimpleGeneratorHostKeyProvider keyProvider = new SimpleGeneratorHostKeyProvider();
        keyProvider.setPath(Objects.requireNonNull(path, "No path"));
        keyProvider.setAlgorithm(DEFAULT_TEST_HOST_KEY_PROVIDER_ALGORITHM);
        keyProvider.setKeySize(DEFAULT_TEST_HOST_KEY_SIZE);
        return validateKeyPairProvider(keyProvider);
    }

    public static KeyPair getFirstKeyPair(KeyPairProviderHolder holder) {
        return getFirstKeyPair(Objects.requireNonNull(holder, "No holder").getKeyPairProvider());
    }

    public static KeyPair getFirstKeyPair(KeyIdentityProvider provider) {
        Objects.requireNonNull(provider, "No key pair provider");
        Iterable<? extends KeyPair> pairs;
        try {
            pairs = Objects.requireNonNull(provider.loadKeys(null), "No loaded keys");
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(
                    "Unexpected " + e.getClass().getSimpleName() + ")"
                                       + " keys loading exception: " + e.getMessage(),
                    e);
        }

        Iterator<? extends KeyPair> iter = Objects.requireNonNull(pairs.iterator(), "No keys iterator");
        ValidateUtils.checkTrue(iter.hasNext(), "Empty loaded kyes iterator");
        return Objects.requireNonNull(iter.next(), "No key pair in iterator");
    }

    private static Path getFile(String resource) {
        URL url = CommonTestSupportUtils.class.getClassLoader().getResource(resource);
        try {
            return Paths.get(url.toURI());
        } catch (URISyntaxException e) {
            return Paths.get(url.getPath());
        }
    }

    /**
     * Removes the specified file - if it is a directory, then its children are deleted recursively and then the
     * directory itself.
     *
     * @param  path        The file {@link Path} to be deleted - ignored if {@code null} or does not exist anymore
     * @param  options     The {@link LinkOption}s to use
     * @return             The <tt>path</tt> argument
     * @throws IOException If failed to access/remove some file(s)
     */
    public static Path deleteRecursive(Path path, LinkOption... options) throws IOException {
        if ((path == null) || (!Files.exists(path))) {
            return path;
        }

        if (Files.isDirectory(path)) {
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(path)) {
                for (Path child : ds) {
                    deleteRecursive(child, options);
                }
            }
        }

        try {
            // seems that if a file is not writable it cannot be deleted
            if (!Files.isWritable(path)) {
                path.toFile().setWritable(true, false);
            }
            Files.delete(path);
        } catch (IOException e) {
            // same logic as deleteRecursive(File) which does not check if deletion succeeded
            System.err.append("Failed (").append(e.getClass().getSimpleName()).append(")")
                    .append(" to delete ").append(path.toString())
                    .append(": ").println(e.getMessage());
        }

        return path;
    }

    public static String resolveRelativeRemotePath(Path root, Path file) {
        Path relPath = root.relativize(file);
        return relPath.toString().replace(File.separatorChar, '/');
    }

    public static FileKeyPairProvider createTestKeyPairProvider(String resource) {
        Path file = getFile(resource);
        file = file.toAbsolutePath();
        String filePath = Objects.toString(file, "");
        FileKeyPairProvider provider = PROVIDERS_MAP.get(filePath);
        if (provider != null) {
            return provider;
        }

        provider = new FileKeyPairProvider();
        provider.setPaths(Collections.singletonList(file));
        provider = validateKeyPairProvider(provider);

        FileKeyPairProvider prev = PROVIDERS_MAP.put(filePath, provider);
        if (prev != null) { // check if somebody else beat us to it
            return prev;
        } else {
            return provider;
        }
    }

    public static <P extends KeyIdentityProvider> P validateKeyPairProvider(P provider) {
        Objects.requireNonNull(provider, "No provider");

        // get the I/O out of the way
        Iterable<KeyPair> keys;
        try {
            keys = Objects.requireNonNull(provider.loadKeys(null), "No keys loaded");
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(
                    "Unexpected " + e.getClass().getSimpleName() + ")"
                                       + " keys loading exception: " + e.getMessage(),
                    e);
        }

        if (keys instanceof Collection<?>) {
            ValidateUtils.checkNotNullAndNotEmpty((Collection<?>) keys, "Empty keys loaded");
        }

        return provider;
    }

    public static Random getRandomizerInstance() {
        Factory<Random> factory = SecurityUtils.getRandomFactory();
        return factory.create();
    }

    /**
     * @param  path        The {@link Path} to write the data to
     * @param  data        The data to write (as UTF-8)
     * @return             The UTF-8 data bytes
     * @throws IOException If failed to write
     */
    public static byte[] writeFile(Path path, String data) throws IOException {
        try (OutputStream fos = Files.newOutputStream(path, IoUtils.EMPTY_OPEN_OPTIONS)) {
            byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
            fos.write(bytes);
            return bytes;
        }
    }

    /**
     * Checks that the key pair can be used to successfully validate a signature
     *
     * @param  kp        The {@link KeyPair}
     * @return           An {@link Optional} holding the verification result - if empty then no appropriate signer was
     *                   found for the keys.
     * @throws Exception If failed to generate the signature
     */
    public static Optional<Boolean> verifySignatureMatch(KeyPair kp) throws Exception {
        return verifySignatureMatch(kp.getPrivate(), kp.getPublic());
    }

    public static Optional<Boolean> verifySignatureMatch(
            PrivateKey privateKey, PublicKey publicKey)
            throws Exception {
        Objects.requireNonNull(privateKey, "No private key provided");
        Objects.requireNonNull(publicKey, "No public key provided");

        // Use check only the private key so we can detect if "mixed" keys are used by failing the verification
        if (privateKey instanceof RSAPrivateKey) {
            return Optional.of(verifySignatureMatch(privateKey, publicKey, BuiltinSignatures.rsa));
        } else if (privateKey instanceof DSAPrivateKey) {
            return Optional.of(verifySignatureMatch(privateKey, publicKey, BuiltinSignatures.dsa));
        } else if (SecurityUtils.isECCSupported() && (privateKey instanceof ECKey)) {
            ECCurves curve = ECCurves.fromECKey((ECKey) privateKey);
            ValidateUtils.checkNotNull(curve, "Unsupported EC key: %s", privateKey);
            switch (curve) {
                case nistp256:
                    return Optional.of(verifySignatureMatch(privateKey, publicKey, BuiltinSignatures.nistp256));
                case nistp384:
                    return Optional.of(verifySignatureMatch(privateKey, publicKey, BuiltinSignatures.nistp384));
                case nistp521:
                    return Optional.of(verifySignatureMatch(privateKey, publicKey, BuiltinSignatures.nistp521));
                default: // ignore
            }
        } else if (SecurityUtils.isEDDSACurveSupported() && (privateKey instanceof EdDSAPrivateKey)) {
            return Optional.of(verifySignatureMatch(privateKey, publicKey, BuiltinSignatures.ed25519));
        }

        return Optional.empty();
    }

    public static boolean verifySignatureMatch(
            PrivateKey privateKey, PublicKey publicKey, Factory<? extends Signature> factory)
            throws Exception {
        Signature signer = factory.create();
        signer.initSigner(null, privateKey);

        byte[] msg = ("[" + privateKey + "][" + publicKey + "]@" + signer).getBytes(StandardCharsets.UTF_8);
        signer.update(null, msg);
        byte[] signature = signer.sign(null);

        Signature verifier = factory.create();
        verifier.initVerifier(null, publicKey);
        verifier.update(null, msg);
        return verifier.verify(null, signature);
    }

    // clears the sensitive data regardless of success/failure
    public static void writeSensitiveDataToFile(Path file, byte[] sensitiveData)
            throws IOException {
        try (ByteChannel out = Files.newByteChannel(file,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            ByteBuffer buf = ByteBuffer.wrap(sensitiveData);
            while (buf.hasRemaining()) {
                out.write(buf);
            }
        } finally {
            Arrays.fill(sensitiveData, (byte) 0);
        }
    }
}
