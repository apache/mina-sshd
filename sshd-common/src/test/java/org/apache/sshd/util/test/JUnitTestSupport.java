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
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyPair;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.BiPredicate;

import org.apache.sshd.common.config.keys.BuiltinIdentities;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.logging.LoggingUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@RunWith(JUnit4SingleInstanceClassRunner.class)
public abstract class JUnitTestSupport extends Assert {
    public static final String TEMP_SUBFOLDER_NAME = "temp";
    public static final boolean OUTPUT_DEBUG_MESSAGES
            = Boolean.parseBoolean(System.getProperty("org.apache.sshd.test.outputDebugMessages", "false"));
    public static final String MAIN_SUBFOLDER = "main";
    public static final String TEST_SUBFOLDER = "test";
    public static final String RESOURCES_SUBFOLDER = "resources";

    public static final org.slf4j.event.Level DEFAULT_LOGGING_LEVEL = org.slf4j.event.Level.INFO;

    // useful test sizes for keys
    public static final List<Integer> DSS_SIZES = Collections.unmodifiableList(Arrays.asList(512, 768, 1024));
    public static final List<Integer> RSA_SIZES = Collections.unmodifiableList(Arrays.asList(1024, 2048, 3072, 4096));
    public static final List<Integer> ED25519_SIZES = Collections.unmodifiableList(Arrays.asList(256));

    @Rule
    public final TestName testNameHolder = new TestName();

    private Path targetFolder;
    private Path tempFolder;

    protected JUnitTestSupport() {
        replaceJULLoggers();
    }

    @BeforeClass
    public static void setupRootLoggerLevel() {
        String levelName = System.getProperty(
                "org.apache.sshd.test.root.log.level", DEFAULT_LOGGING_LEVEL.toString());
        org.slf4j.event.Level level = LoggingUtils.slf4jLevelFromName(levelName);
        if (level == null) {
            level = DEFAULT_LOGGING_LEVEL;
        }

        replaceJULLoggers();

        Logger rootLogger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        if (rootLogger instanceof ch.qos.logback.classic.Logger) {
            Class<?> clazz = rootLogger.getClass();
            ch.qos.logback.classic.Level rawLevel = getRawLoggerLevel(level);
            ((ch.qos.logback.classic.Logger) rootLogger).setLevel(rawLevel);
            rootLogger.info("Using {} logger(s) at level={}", clazz.getName(), rawLevel);
        }
    }

    public static ch.qos.logback.classic.Level getRawLoggerLevel(org.slf4j.event.Level level) {
        if (org.slf4j.event.Level.ERROR.equals(level)) {
            return ch.qos.logback.classic.Level.ERROR;
        } else if (org.slf4j.event.Level.WARN.equals(level)) {
            return ch.qos.logback.classic.Level.WARN;
        } else if (org.slf4j.event.Level.INFO.equals(level)) {
            return ch.qos.logback.classic.Level.INFO;
        } else if (org.slf4j.event.Level.DEBUG.equals(level)) {
            return ch.qos.logback.classic.Level.DEBUG;
        } else if (org.slf4j.event.Level.TRACE.equals(level)) {
            return ch.qos.logback.classic.Level.TRACE;
        } else {
            return ch.qos.logback.classic.Level.INFO;
        }

    }

    public final String getCurrentTestName() {
        return testNameHolder.getMethodName();
    }

    /**
     * Attempts to build a <U>relative</U> path whose root is the location of the TEMP sub-folder of the Maven
     * &quot;target&quot; folder associated with the project
     *
     * @param  comps The path components - ignored if {@code null}/empty
     * @return       The {@link Path} representing the result - same as target folder if no components
     * @see          #TEMP_SUBFOLDER_NAME
     * @see          #getTargetRelativeFile(Collection)
     */
    protected Path getTempTargetRelativeFile(String... comps) {
        return getTempTargetRelativeFile(GenericUtils.isEmpty(comps) ? Collections.emptyList() : Arrays.asList(comps));
    }

    /**
     * Attempts to build a <U>relative</U> path whose root is the location of the TEMP sub-folder of the Maven
     * &quot;target&quot; folder associated with the project
     *
     * @param  comps The path components - ignored if {@code null}/empty
     * @return       The {@link Path} representing the result - same as target folder if no components
     * @see          #TEMP_SUBFOLDER_NAME
     * @see          #getTempTargetFolder()
     */
    protected Path getTempTargetRelativeFile(Collection<String> comps) {
        return CommonTestSupportUtils.resolve(getTempTargetFolder(), comps);
    }

    /**
     * @return The TEMP sub-folder {@link Path} of the Maven &quot;target&quot; folder associated with the project -
     *         never {@code null}
     */
    protected Path getTempTargetFolder() {
        synchronized (TEMP_SUBFOLDER_NAME) {
            if (tempFolder == null) {
                tempFolder = Objects.requireNonNull(detectTargetFolder(), "No target folder detected")
                        .resolve(TEMP_SUBFOLDER_NAME);
            }
        }

        return tempFolder;
    }

    /**
     * Attempts to build a <U>relative</U> path whose root is the location of the Maven &quot;target&quot; folder
     * associated with the project
     *
     * @param  comps The path components - ignored if {@code null}/empty
     * @return       The {@link Path} representing the result - same as target folder if no components
     */
    protected Path getTargetRelativeFile(String... comps) {
        return getTargetRelativeFile(GenericUtils.isEmpty(comps) ? Collections.emptyList() : Arrays.asList(comps));
    }

    /**
     * Attempts to build a <U>relative</U> path whose root is the location of the Maven &quot;target&quot; folder
     * associated with the project
     *
     * @param  comps The path components - ignored if {@code null}/empty
     * @return       The {@link Path} representing the result - same as target folder if no components
     * @see          #detectTargetFolder()
     */
    protected Path getTargetRelativeFile(Collection<String> comps) {
        return CommonTestSupportUtils.resolve(detectTargetFolder(), comps);
    }

    /**
     * Attempts to detect the location of the Maven &quot;target&quot; folder associated with the project that contains
     * the actual class extending this base class
     *
     * @return                          The {@link File} representing the location of the &quot;target&quot; folder
     * @throws IllegalArgumentException If failed to detect the folder
     */
    protected Path detectTargetFolder() throws IllegalArgumentException {
        synchronized (TEMP_SUBFOLDER_NAME) {
            if (targetFolder == null) {
                Path path = CommonTestSupportUtils.detectTargetFolder(getClass());
                targetFolder = Objects.requireNonNull(path, "Failed to detect target folder");
            }
        }

        return targetFolder;
    }

    /**
     * Creates a folder bearing the class's simple name under the project's target temporary folder
     *
     * @return             The created folder {@link Path}
     * @throws IOException If failed to detect or create the folder's location
     * @see                #detectTargetFolder() detectTargetFolder
     * @see                #assertHierarchyTargetFolderExists(Path, LinkOption...) assertHierarchyTargetFolderExists
     */
    protected Path createTempClassFolder() throws IOException {
        Path tmpDir = getTempTargetFolder();
        return assertHierarchyTargetFolderExists(tmpDir.resolve(getClass().getSimpleName()));
    }

    protected Path detectSourcesFolder() throws IllegalStateException {
        Path target = detectTargetFolder();
        Path parent = target.getParent();
        return parent.resolve("src");
    }

    protected Path getTestResourcesFolder() {
        Path target = detectTargetFolder();
        String pkgFolder = getClass().getPackage().getName().replace('.', File.separatorChar);
        return target.resolve("test-classes").resolve(pkgFolder);
    }

    protected Path getClassResourcesFolder(String resType /* test or main */) {
        return getClassResourcesFolder(resType, getClass());
    }

    protected Path getClassResourcesFolder(String resType /* test or main */, Class<?> clazz) {
        return getPackageResourcesFolder(resType, clazz.getPackage());
    }

    protected Path getPackageResourcesFolder(String resType /* test or main */, Package pkg) {
        return getPackageResourcesFolder(resType, pkg.getName());
    }

    protected Path getPackageResourcesFolder(String resType /* test or main */, String pkgName) {
        Path src = detectSourcesFolder();
        Path root = src.resolve(resType);
        Path resources = root.resolve(RESOURCES_SUBFOLDER);
        return resources.resolve(pkgName.replace('.', File.separatorChar));
    }

    protected KeyPairProvider createTestHostKeyProvider() {
        return CommonTestSupportUtils.createTestHostKeyProvider(getClass());
    }

    /* ------------------- Useful extra test helpers ---------------------- */

    public static String shuffleCase(CharSequence cs) {
        if (GenericUtils.isEmpty(cs)) {
            return "";
        }

        StringBuilder sb = new StringBuilder(cs.length());
        for (int index = 0; index < cs.length(); index++) {
            char ch = cs.charAt(index);
            double v = Math.random();
            if (Double.compare(v, 0.3d) < 0) {
                ch = Character.toUpperCase(ch);
            } else if ((Double.compare(v, 0.3d) >= 0) && (Double.compare(v, 0.6d) < 0)) {
                ch = Character.toLowerCase(ch);
            }
            sb.append(ch);
        }

        return sb.toString();
    }

    public static String repeat(CharSequence csq, int nTimes) {
        if (GenericUtils.isEmpty(csq) || (nTimes <= 0)) {
            return "";
        }

        StringBuilder sb = new StringBuilder(nTimes * csq.length());
        for (int index = 0; index < nTimes; index++) {
            sb.append(csq);
        }

        return sb.toString();
    }

    public static List<Object[]> parameterize(Collection<?> params) {
        if (GenericUtils.isEmpty(params)) {
            return Collections.emptyList();
        }

        List<Object[]> result = new ArrayList<>(params.size());
        for (Object p : params) {
            result.add(new Object[] { p });
        }

        return result;
    }

    /* ----------------------- Useful extra assertions --------------------- */

    public static void assertEquals(String message, boolean expected, boolean actual) {
        assertEquals(message, Boolean.valueOf(expected), Boolean.valueOf(actual));
    }

    public static <T> void assertEquals(String message, Iterable<? extends T> expected, Iterable<? extends T> actual) {
        if (expected != actual) {
            assertEquals(message, expected.iterator(), actual.iterator());
        }
    }

    public static <T> void assertEquals(String message, Iterator<? extends T> expected, Iterator<? extends T> actual) {
        if (expected == actual) {
            return;
        }

        for (int index = 0; expected.hasNext(); index++) {
            assertTrue(message + "[next actual index=" + index + "]", actual.hasNext());

            T expValue = expected.next();
            T actValue = actual.next();
            assertEquals(message + "[iterator index=" + index + "]", expValue, actValue);
        }

        // once expected is exhausted make sure no more actual items left
        assertFalse(message + "[non-empty-actual]", actual.hasNext());
    }

    public static Path assertHierarchyTargetFolderExists(Path folder, LinkOption... options) throws IOException {
        if (Files.exists(folder, options)) {
            assertTrue("Target is an existing file instead of a folder: " + folder, Files.isDirectory(folder, options));
        } else {
            Files.createDirectories(folder);
        }

        return folder;
    }

    public static void assertFileContentsEquals(String prefix, Path expected, Path actual) throws IOException {
        long cmpSize = Files.size(expected);
        assertEquals(prefix + ": Mismatched file size", cmpSize, Files.size(expected));

        try (InputStream expStream = Files.newInputStream(expected);
             InputStream actStream = Files.newInputStream(actual)) {
            byte[] expData = new byte[IoUtils.DEFAULT_COPY_SIZE];
            byte[] actData = new byte[expData.length];

            for (long offset = 0L; offset < cmpSize;) {
                Arrays.fill(expData, (byte) 0);
                int expLen = expStream.read(expData);
                Arrays.fill(actData, (byte) 0);
                int actLen = actStream.read(actData);
                assertEquals(prefix + ": Mismatched read size at offset=" + offset, expLen, actLen);
                assertArrayEquals(prefix + ": Mismatched data at offset=" + offset, expData, actData);

                offset += expLen;
            }
        }
    }

    public static File assertHierarchyTargetFolderExists(File folder) {
        if (folder.exists()) {
            assertTrue("Target is an existing file instead of a folder: " + folder.getAbsolutePath(), folder.isDirectory());
        } else {
            assertTrue("Failed to create hierarchy of " + folder.getAbsolutePath(), folder.mkdirs());
        }

        return folder;
    }

    public static <T> T assertObjectInstanceOf(String message, Class<? extends T> expected, Object obj) {
        assertNotNull(message + " - no actual object", obj);

        Class<?> actual = obj.getClass();
        if (!expected.isAssignableFrom(actual)) {
            fail(message + " - actual object type (" + actual.getName() + ") incompatible with expected (" + expected.getName()
                 + ")");
        }

        return expected.cast(obj);
    }

    public static <E> void assertListEquals(String message, List<? extends E> expected, List<? extends E> actual) {
        assertListEquals(message, expected, actual, Objects::equals);
    }

    public static <E> void assertListEquals(
            String message, List<? extends E> expected, List<? extends E> actual, BiPredicate<? super E, ? super E> equator) {
        int expSize = GenericUtils.size(expected);
        int actSize = GenericUtils.size(actual);
        assertEquals(message + "[size]", expSize, actSize);

        for (int index = 0; index < expSize; index++) {
            E expValue = expected.get(index);
            E actValue = actual.get(index);
            if (!equator.test(expValue, actValue)) {
                fail(message + "[" + index + "]: expected=" + expValue + ", actual=" + actValue);
            }
        }
    }

    public static <K, V> void assertMapEquals(
            String message, Map<? extends K, ? extends V> expected, Map<? super K, ? extends V> actual) {
        assertMapEquals(message, expected, actual, Objects::equals);
    }

    public static <K, V> void assertMapEquals(
            String message, Map<? extends K, ? extends V> expected, Map<? super K, ? extends V> actual,
            BiPredicate<? super V, ? super V> equator) {
        int numItems = GenericUtils.size(expected);
        assertEquals(message + "[size]", numItems, GenericUtils.size(actual));

        if (numItems > 0) {
            expected.forEach((key, expValue) -> {
                V actValue = actual.get(key);
                if (!equator.test(expValue, actValue)) {
                    fail(message + "[" + key + "]: expected=" + expValue + ", actual=" + actValue);
                }
            });
        }
    }

    public static void assertKeyPairEquals(String message, KeyPair expected, KeyPair actual) {
        assertKeyEquals(message + "[public]", expected.getPublic(), actual.getPublic());
        assertKeyEquals(message + "[private]", expected.getPrivate(), actual.getPrivate());
    }

    public static void assertKeyEncodingEquals(String message, Key expected, Key actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[format]", expected.getFormat(), actual.getFormat());
        assertArrayEquals(message + "[encoded-data]", expected.getEncoded(), actual.getEncoded());
    }

    public static <T extends Key> void assertKeyListEquals(
            String message, List<? extends T> expected, List<? extends T> actual) {
        int numKeys = GenericUtils.size(expected);
        assertEquals(message + "[size]", numKeys, GenericUtils.size(actual));
        if (numKeys <= 0) {
            return;
        }

        for (int index = 0; index < numKeys; index++) {
            assertKeyEquals(message + "[#" + index + "]", expected.get(index), actual.get(index));
        }
    }

    public static <T extends Key> void assertKeyEquals(String message, T expected, T actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[algorithm]",
                resolveEffectiveAlgorithm(expected.getAlgorithm()),
                resolveEffectiveAlgorithm(actual.getAlgorithm()));

        if (expected instanceof RSAPublicKey) {
            assertRSAPublicKeyEquals(message, RSAPublicKey.class.cast(expected), RSAPublicKey.class.cast(actual));
        } else if (expected instanceof DSAPublicKey) {
            assertDSAPublicKeyEquals(message, DSAPublicKey.class.cast(expected), DSAPublicKey.class.cast(actual));
        } else if (expected instanceof ECPublicKey) {
            assertECPublicKeyEquals(message, ECPublicKey.class.cast(expected), ECPublicKey.class.cast(actual));
        } else if (expected instanceof RSAPrivateKey) {
            assertRSAPrivateKeyEquals(message, RSAPrivateKey.class.cast(expected), RSAPrivateKey.class.cast(actual));
        } else if (expected instanceof DSAPrivateKey) {
            assertDSAPrivateKeyEquals(message, DSAPrivateKey.class.cast(expected), DSAPrivateKey.class.cast(actual));
        } else if (expected instanceof ECPrivateKey) {
            assertECPrivateKeyEquals(message, ECPrivateKey.class.cast(expected), ECPrivateKey.class.cast(actual));
        }
    }

    public static KeyPair validateKeyPairSignable(Object hint, KeyPair kp) throws Exception {
        assertNotNull(hint + ": no key pair provided", kp);
        Optional<Boolean> signable = CommonTestSupportUtils.verifySignatureMatch(kp);
        // if no result then assume "OK"
        assertTrue(hint + ": Failed to validate signature", signable.orElse(Boolean.TRUE));
        return kp;
    }

    public static String resolveEffectiveAlgorithm(String algorithm) {
        if (GenericUtils.isEmpty(algorithm)) {
            return algorithm;
        } else if (BuiltinIdentities.Constants.ECDSA.equalsIgnoreCase(algorithm)) {
            return KeyUtils.EC_ALGORITHM;
        } else {
            return algorithm.toUpperCase(Locale.ENGLISH);
        }
    }

    public static void assertRSAPublicKeyEquals(String message, RSAPublicKey expected, RSAPublicKey actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[e]", expected.getPublicExponent(), actual.getPublicExponent());
        assertEquals(message + "[n]", expected.getModulus(), actual.getModulus());
    }

    public static void assertDSAPublicKeyEquals(String message, DSAPublicKey expected, DSAPublicKey actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[y]", expected.getY(), actual.getY());
        assertDSAParamsEquals(message + "[params]", expected.getParams(), actual.getParams());
    }

    public static void assertECPublicKeyEquals(String message, ECPublicKey expected, ECPublicKey actual) {
        if (expected == actual) {
            return;
        }

        assertECPointEquals(message + "[W]", expected.getW(), actual.getW());
        assertECParameterSpecEquals(message, expected, actual);
    }

    public static void assertRSAPrivateKeyEquals(String message, RSAPrivateKey expected, RSAPrivateKey actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[d]", expected.getPrivateExponent(), actual.getPrivateExponent());
        assertEquals(message + "[n]", expected.getModulus(), actual.getModulus());
    }

    public static void assertDSAPrivateKeyEquals(String message, DSAPrivateKey expected, DSAPrivateKey actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[x]", expected.getX(), actual.getX());
        assertDSAParamsEquals(message + "[params]", expected.getParams(), actual.getParams());
    }

    public static void assertDSAParamsEquals(String message, DSAParams expected, DSAParams actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[g]", expected.getG(), actual.getG());
        assertEquals(message + "[p]", expected.getP(), actual.getP());
        assertEquals(message + "[q]", expected.getQ(), actual.getQ());
    }

    public static void assertECPrivateKeyEquals(String message, ECPrivateKey expected, ECPrivateKey actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[S]", expected.getS(), actual.getS());
        assertECParameterSpecEquals(message, expected, actual);
    }

    public static void assertECParameterSpecEquals(String message, ECKey expected, ECKey actual) {
        if (expected == actual) {
            return;
        }
        assertECParameterSpecEquals(message, expected.getParams(), actual.getParams());
    }

    public static void assertECParameterSpecEquals(String message, ECParameterSpec expected, ECParameterSpec actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[order]", expected.getOrder(), actual.getOrder());
        assertEquals(message + "[cofactor]", expected.getCofactor(), actual.getCofactor());
        assertECPointEquals(message + "[generator]", expected.getGenerator(), actual.getGenerator());
        assertCurveEquals(message + "[curve]", expected.getCurve(), actual.getCurve());
    }

    public static void assertCurveEquals(String message, EllipticCurve expected, EllipticCurve actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[A]", expected.getA(), actual.getA());
        assertEquals(message + "[B]", expected.getB(), actual.getB());
        assertArrayEquals(message + "[seed]", expected.getSeed(), actual.getSeed());
        assertECFieldEquals(message + "[field]", expected.getField(), actual.getField());
    }

    public static void assertECFieldEquals(String message, ECField expected, ECField actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[size]", expected.getFieldSize(), actual.getFieldSize());
    }

    public static void assertECPointEquals(String message, ECPoint expected, ECPoint actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[x]", expected.getAffineX(), actual.getAffineX());
        assertEquals(message + "[y]", expected.getAffineY(), actual.getAffineY());
    }

    public static void assertFileLength(File file, long length, long timeout) throws Exception {
        assertFileLength(file.toPath(), length, timeout);
    }

    public static void assertFileLength(File file, long length, Duration timeout) throws Exception {
        assertFileLength(file.toPath(), length, timeout);
    }

    /**
     * Waits the specified timeout for the file to exist and have the required length
     *
     * @param  file      The file {@link Path} to check
     * @param  length    Expected length
     * @param  timeout   Timeout (msec.) to wait for satisfying the requirements
     * @throws Exception If failed to access the file
     */
    public static void assertFileLength(Path file, long length, Duration timeout) throws Exception {
        assertFileLength(file, length, timeout.toMillis());
    }

    public static void assertFileLength(Path file, long length, long timeout) throws Exception {
        if (waitForFile(file, length, timeout)) {
            return;
        }
        assertTrue("File not found: " + file, Files.exists(file));
        assertEquals("Mismatched file size for " + file, length, Files.size(file));
    }

    public static boolean waitForFile(Path file, long length, Duration timeout) throws Exception {
        return waitForFile(file, length, timeout.toMillis());
    }

    public static boolean waitForFile(Path file, long length, long timeout) throws Exception {
        while (timeout > 0L) {
            long sleepTime = Math.min(timeout, 100L);
            if (Files.exists(file) && (Files.size(file) == length)) {
                return true;
            }

            long sleepStart = System.nanoTime();
            Thread.sleep(sleepTime);
            long sleepEnd = System.nanoTime();
            long nanoSleep = sleepEnd - sleepStart;

            sleepTime = TimeUnit.NANOSECONDS.toMillis(nanoSleep);
            if (sleepTime <= 0L) {
                timeout -= 10L;
            } else {
                timeout -= sleepTime;
            }
        }

        return false;
    }

    /* ---------------------------------------------------------------------------- */

    public static void outputDebugMessage(String format, Object o) {
        if (OUTPUT_DEBUG_MESSAGES) {
            outputDebugMessage(String.format(format, o));
        }
    }

    public static void outputDebugMessage(String format, Object... args) {
        if (OUTPUT_DEBUG_MESSAGES) {
            outputDebugMessage(String.format(format, args));
        }
    }

    public static void outputDebugMessage(Object message) {
        if (OUTPUT_DEBUG_MESSAGES) {
            System.out.append("===[DEBUG]=== ").println(message);
        }
    }

    /* ---------------------------------------------------------------------------- */

    public static void replaceJULLoggers() {
        if (!SLF4JBridgeHandler.isInstalled()) {
            // Optionally remove existing handlers attached to j.u.l root logger
            SLF4JBridgeHandler.removeHandlersForRootLogger();  // (since SLF4J 1.6.5)

            // add SLF4JBridgeHandler to j.u.l's root logger, should be done once during
            // the initialization phase of your application
            SLF4JBridgeHandler.install();
        }
    }
}
