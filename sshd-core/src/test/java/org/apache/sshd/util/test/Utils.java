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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.CodeSource;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.ProtectionDomain;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.config.hosts.HostConfigEntryResolver;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.AbstractFileKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyPairProviderHolder;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;

public final class Utils {
    /**
     * URL/URI scheme that refers to a file
     */
    public static final String FILE_URL_SCHEME = "file";
    /**
     * Prefix used in URL(s) that reference a file resource
     */
    public static final String FILE_URL_PREFIX = FILE_URL_SCHEME + ":";

    /**
     * Separator used in URL(s) that reference a resource inside a JAR
     * to denote the sub-path inside the JAR
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

    public static final List<String> TARGET_FOLDER_NAMES =    // NOTE: order is important
            Collections.unmodifiableList(
                    Arrays.asList("target" /* Maven */, "build" /* Gradle */));

    public static final String DEFAULT_TEST_HOST_KEY_PROVIDER_ALGORITHM = KeyUtils.RSA_ALGORITHM;
    // uses a cached instance to avoid re-creating the keys as it is a time-consuming effort
    private static final AtomicReference<KeyPairProvider> KEYPAIR_PROVIDER_HOLDER = new AtomicReference<KeyPairProvider>();
    // uses a cached instance to avoid re-creating the keys as it is a time-consuming effort
    private static final Map<String, AbstractFileKeyPairProvider> PROVIDERS_MAP = new ConcurrentHashMap<String, AbstractFileKeyPairProvider>();

    private Utils() {
        throw new UnsupportedOperationException("No instance");
    }

    public static KeyPairProvider createTestHostKeyProvider(Class<?> anchor) {
        KeyPairProvider provider = KEYPAIR_PROVIDER_HOLDER.get();
        if (provider != null) {
            return provider;
        }

        File targetFolder = ValidateUtils.checkNotNull(detectTargetFolder(anchor), "Failed to detect target folder");
        File file = new File(targetFolder, "hostkey." + DEFAULT_TEST_HOST_KEY_PROVIDER_ALGORITHM.toLowerCase());
        provider = createTestHostKeyProvider(file);

        KeyPairProvider prev = KEYPAIR_PROVIDER_HOLDER.getAndSet(provider);
        if (prev != null) { // check if somebody else beat us to it
            return prev;
        } else {
            return provider;
        }
    }

    public static KeyPairProvider createTestHostKeyProvider(File file) {
        return createTestHostKeyProvider(ValidateUtils.checkNotNull(file, "No file").toPath());
    }

    public static KeyPairProvider createTestHostKeyProvider(Path path) {
        SimpleGeneratorHostKeyProvider keyProvider = new SimpleGeneratorHostKeyProvider();
        keyProvider.setPath(ValidateUtils.checkNotNull(path, "No path"));
        keyProvider.setAlgorithm(DEFAULT_TEST_HOST_KEY_PROVIDER_ALGORITHM);
        return validateKeyPairProvider(keyProvider);
    }

    public static KeyPair getFirstKeyPair(KeyPairProviderHolder holder) {
        return getFirstKeyPair(ValidateUtils.checkNotNull(holder, "No holder").getKeyPairProvider());
    }

    public static KeyPair getFirstKeyPair(KeyIdentityProvider provider) {
        ValidateUtils.checkNotNull(provider, "No key pair provider");
        Iterable<? extends KeyPair> pairs = ValidateUtils.checkNotNull(provider.loadKeys(), "No loaded keys");
        Iterator<? extends KeyPair> iter = ValidateUtils.checkNotNull(pairs.iterator(), "No keys iterator");
        ValidateUtils.checkTrue(iter.hasNext(), "Empty loaded kyes iterator");
        return ValidateUtils.checkNotNull(iter.next(), "No key pair in iterator");
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

    public static AbstractFileKeyPairProvider createTestKeyPairProvider(String resource) {
        File file = getFile(resource);
        String filePath = file.getAbsolutePath();
        AbstractFileKeyPairProvider provider = PROVIDERS_MAP.get(filePath);
        if (provider != null) {
            return provider;
        }

        provider = SecurityUtils.createFileKeyPairProvider();
        provider.setFiles(Collections.singletonList(file));
        provider = validateKeyPairProvider(provider);

        AbstractFileKeyPairProvider prev = PROVIDERS_MAP.put(filePath, provider);
        if (prev != null) { // check if somebody else beat us to it
            return prev;
        } else {
            return provider;
        }
    }

    private static <P extends KeyIdentityProvider> P validateKeyPairProvider(P provider) {
        ValidateUtils.checkNotNull(provider, "No provider");

        // get the I/O out of the way
        Iterable<KeyPair> keys = ValidateUtils.checkNotNull(provider.loadKeys(), "No keys loaded");
        if (keys instanceof Collection<?>) {
            ValidateUtils.checkNotNullAndNotEmpty((Collection<?>) keys, "Empty keys loaded");
        }

        return provider;
    }

    public static Random getRandomizerInstance() {
        Factory<Random> factory = SecurityUtils.getRandomFactory();
        return factory.create();
    }

    public static int getFreePort() throws Exception {
        try (ServerSocket s = new ServerSocket()) {
            s.setReuseAddress(true);
            s.bind(new InetSocketAddress((InetAddress) null, 0));
            return s.getLocalPort();
        }
    }

    private static File getFile(String resource) {
        URL url = Utils.class.getClassLoader().getResource(resource);
        try {
            return new File(url.toURI());
        } catch (URISyntaxException e) {
            return new File(url.getPath());
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

    public static File resolve(File root, String... children) {
        if (GenericUtils.isEmpty(children)) {
            return root;
        } else {
            return resolve(root, Arrays.asList(children));
        }
    }

    public static File resolve(File root, Collection<String> children) {
        File path = root;
        if (!GenericUtils.isEmpty(children)) {
            for (String child : children) {
                path = new File(path, child);
            }
        }

        return path;
    }

    /**
     * Removes the specified file - if it is a directory, then its children
     * are deleted recursively and then the directory itself. <B>Note:</B>
     * no attempt is made to make sure that {@link File#delete()} was successful
     *
     * @param file The {@link File} to be deleted - ignored if {@code null}
     *             or does not exist anymore
     * @return The <tt>file</tt> argument
     */
    public static File deleteRecursive(File file) {
        if ((file == null) || (!file.exists())) {
            return file;
        }

        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (!GenericUtils.isEmpty(children)) {
                for (File child : children) {
                    deleteRecursive(child);
                }
            }
        }

        // seems that if a file is not writable it cannot be deleted
        if (!file.canWrite()) {
            file.setWritable(true, false);
        }

        if (!file.delete()) {
            System.err.append("Failed to delete ").println(file.getAbsolutePath());
        }

        return file;
    }

    /**
     * Removes the specified file - if it is a directory, then its children
     * are deleted recursively and then the directory itself.
     *
     * @param path    The file {@link Path} to be deleted - ignored if {@code null}
     *                or does not exist anymore
     * @param options The {@link LinkOption}s to use
     * @return The <tt>path</tt> argument
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

    /**
     * @param anchor An anchor {@link Class} whose container we want to use
     *               as the starting point for the &quot;target&quot; folder lookup up the
     *               hierarchy
     * @return The &quot;target&quot; <U>folder</U> - {@code null} if not found
     * @see #detectTargetFolder(File)
     */
    public static File detectTargetFolder(Class<?> anchor) {
        return detectTargetFolder(getClassContainerLocationFile(anchor));
    }

    /**
     * @param clazz A {@link Class} object
     * @return A {@link File} of the location of the class bytes container
     * - e.g., the root folder, the containing JAR, etc.. Returns
     * {@code null} if location could not be resolved
     * @throws IllegalArgumentException If location is not a valid
     *                                  {@link File} location
     * @see #getClassContainerLocationURI(Class)
     * @see #toFileSource(URI)
     */
    public static File getClassContainerLocationFile(Class<?> clazz)
            throws IllegalArgumentException {
        try {
            URI uri = getClassContainerLocationURI(clazz);
            return toFileSource(uri);
        } catch (URISyntaxException | MalformedURLException e) {
            throw new IllegalArgumentException(e.getClass().getSimpleName() + ": " + e.getMessage(), e);
        }
    }

    /**
     * @param clazz A {@link Class} object
     * @return A {@link URI} to the location of the class bytes container
     * - e.g., the root folder, the containing JAR, etc.. Returns
     * {@code null} if location could not be resolved
     * @throws URISyntaxException if location is not a valid URI
     * @see #getClassContainerLocationURL(Class)
     */
    public static URI getClassContainerLocationURI(Class<?> clazz) throws URISyntaxException {
        URL url = getClassContainerLocationURL(clazz);
        return (url == null) ? null : url.toURI();
    }

    /**
     * @param clazz A {@link Class} object
     * @return A {@link URL} to the location of the class bytes container
     * - e.g., the root folder, the containing JAR, etc.. Returns
     * {@code null} if location could not be resolved
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
                throw new IllegalArgumentException("getClassContainerLocationURL(" + clazz.getName() + ")"
                        + " Failed to create URL=" + srcForm + " from " + url.toExternalForm()
                        + ": " + e.getMessage());
            }
        }

        return url;
    }

    /**
     * Converts a {@link URL} that may refer to an internal resource to
     * a {@link File} representing is &quot;source&quot; container (e.g.,
     * if it is a resource in a JAR, then the result is the JAR's path)
     *
     * @param url The {@link URL} - ignored if {@code null}
     * @return The matching {@link File}
     * @throws MalformedURLException If source URL does not refer to a
     *                               file location
     * @see #toFileSource(URI)
     */
    public static File toFileSource(URL url) throws MalformedURLException {
        if (url == null) {
            return null;
        }

        try {
            return toFileSource(url.toURI());
        } catch (URISyntaxException e) {
            throw new MalformedURLException("toFileSource(" + url.toExternalForm() + ")"
                    + " cannot (" + e.getClass().getSimpleName() + ")"
                    + " convert to URI: " + e.getMessage());
        }
    }

    /**
     * Converts a {@link URI} that may refer to an internal resource to
     * a {@link File} representing is &quot;source&quot; container (e.g.,
     * if it is a resource in a JAR, then the result is the JAR's path)
     *
     * @param uri The {@link URI} - ignored if {@code null}
     * @return The matching {@link File}
     * @throws MalformedURLException If source URI does not refer to a
     *                               file location
     * @see #getURLSource(URI)
     */
    public static File toFileSource(URI uri) throws MalformedURLException {
        String src = getURLSource(uri);
        if (GenericUtils.isEmpty(src)) {
            return null;
        }

        if (!src.startsWith(FILE_URL_PREFIX)) {
            throw new MalformedURLException("toFileSource(" + src + ") not a '" + FILE_URL_SCHEME + "' scheme");
        }

        try {
            return new File(new URI(src));
        } catch (URISyntaxException e) {
            throw new MalformedURLException("toFileSource(" + src + ")"
                    + " cannot (" + e.getClass().getSimpleName() + ")"
                    + " convert to URI: " + e.getMessage());
        }
    }

    /**
     * @param uri The {@link URI} value - ignored if {@code null}
     * @return The URI(s) source path where {@link #JAR_URL_PREFIX} and
     * any sub-resource are stripped
     * @see #getURLSource(String)
     */
    public static String getURLSource(URI uri) {
        return getURLSource((uri == null) ? null : uri.toString());
    }

    /**
     * @param url The {@link URL} value - ignored if {@code null}
     * @return The URL(s) source path where {@link #JAR_URL_PREFIX} and
     * any sub-resource are stripped
     * @see #getURLSource(String)
     */
    public static String getURLSource(URL url) {
        return getURLSource((url == null) ? null : url.toExternalForm());
    }

    /**
     * @param externalForm The {@link URL#toExternalForm()} string - ignored if
     *                     {@code null}/empty
     * @return The URL(s) source path where {@link #JAR_URL_PREFIX} and
     * any sub-resource are stripped
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
     * @param url A {@link URL} - ignored if {@code null}
     * @return The path after stripping any trailing '/' provided the path
     * is not '/' itself
     * @see #adjustURLPathValue(String)
     */
    public static String adjustURLPathValue(URL url) {
        return adjustURLPathValue((url == null) ? null : url.getPath());
    }

    /**
     * @param path A URL path value - ignored if {@code null}/empty
     * @return The path after stripping any trailing '/' provided the path
     * is not '/' itself
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
     * @param clazz The request {@link Class}
     * @return A {@link URL} to the location of the <code>.class</code> file
     * - {@code null} if location could not be resolved
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
     * @param name The fully qualified class name - ignored if {@code null}/empty
     * @return The relative path of the class file byte-code resource
     */
    public static String getClassBytesResourceName(String name) {
        if (GenericUtils.isEmpty(name)) {
            return name;
        } else {
            return new StringBuilder(name.length() + CLASS_FILE_SUFFIX.length())
                    .append(name.replace('.', '/'))
                    .append(CLASS_FILE_SUFFIX)
                    .toString();
        }
    }

    /**
     * @param anchorFile An anchor {@link File} we want to use
     *                   as the starting point for the &quot;target&quot; or &quot;build&quot; folder
     *                   lookup up the hierarchy
     * @return The &quot;target&quot; <U>folder</U> - {@code null} if not found
     */
    public static File detectTargetFolder(File anchorFile) {
        for (File file = anchorFile; file != null; file = file.getParentFile()) {
            if (!file.isDirectory()) {
                continue;
            }

            String name = file.getName();
            if (TARGET_FOLDER_NAMES.contains(name)) {
                return file;
            }
        }

        return null;
    }

    public static String resolveRelativeRemotePath(Path root, Path file) {
        Path relPath = root.relativize(file);
        return relPath.toString().replace(File.separatorChar, '/');
    }

    public static SshClient setupTestClient(Class<?> anchor) {
        SshClient client = SshClient.setUpDefaultClient();
        client.setServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);
        client.setHostConfigEntryResolver(HostConfigEntryResolver.EMPTY);
        client.setKeyPairProvider(KeyPairProvider.EMPTY_KEYPAIR_PROVIDER);
        return client;
    }

    public static SshServer setupTestServer(Class<?> anchor) {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setKeyPairProvider(createTestHostKeyProvider(anchor));
        sshd.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
        sshd.setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        sshd.setShellFactory(EchoShellFactory.INSTANCE);
        sshd.setCommandFactory(UnknownCommandFactory.INSTANCE);
        return sshd;
    }

    /**
     * @param path The {@link Path} to write the data to
     * @param data The data to write (as UTF-8)
     * @return The UTF-8 data bytes
     * @throws IOException If failed to write
     */
    public static byte[] writeFile(Path path, String data) throws IOException {
        try (OutputStream fos = Files.newOutputStream(path, IoUtils.EMPTY_OPEN_OPTIONS)) {
            byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
            fos.write(bytes);
            return bytes;
        }
    }
}
