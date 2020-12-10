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

package org.apache.sshd.cli.client;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.InterruptedIOException;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.Writer;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.Channel;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;

import org.apache.sshd.cli.CliSupport;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.BuiltinIdentities;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.io.BuiltinIoServiceFactoryFactories;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.common.util.logging.SimplifiedLog;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * A naive implementation of
 * <A HREF="https://www.freebsd.org/cgi/man.cgi?query=ssh-keyscan&sektion=1">ssh-keyscan(1)</A>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshKeyScanMain implements Channel, Callable<Void>, ServerKeyVerifier, SessionListener, SimplifiedLog {
    /**
     * Default key types if not overridden from the command line
     */
    public static final List<String> DEFAULT_KEY_TYPES = Collections.unmodifiableList(
            Arrays.asList(
                    BuiltinIdentities.Constants.RSA,
                    BuiltinIdentities.Constants.ECDSA));
    public static final long DEFAULT_TIMEOUT = TimeUnit.SECONDS.toMillis(5L);
    public static final Level DEFAULT_LEVEL = Level.INFO;

    private final AtomicBoolean open = new AtomicBoolean(true);
    private SshClient client;
    private int port;
    private long timeout;
    private List<String> keyTypes;
    private InputStream input;
    private Level level;
    private final Map<String, String> currentHostFingerprints = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    public SshKeyScanMain() {
        super();
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public InputStream getInputStream() {
        return input;
    }

    public void setInputStream(InputStream input) {
        this.input = input;
    }

    public List<String> getKeyTypes() {
        return keyTypes;
    }

    public void setKeyTypes(List<String> keyTypes) {
        this.keyTypes = keyTypes;
    }

    public long getTimeout() {
        return timeout;
    }

    public void setTimeout(long timeout) {
        this.timeout = timeout;
    }

    public Level getLogLevel() {
        return level;
    }

    public void setLogLevel(Level level) {
        this.level = level;
    }

    @Override
    public void log(Level level, Object message, Throwable t) {
        if (isEnabledLevel(level)) {
            PrintStream ps = System.out;
            if ((t != null) || Level.SEVERE.equals(level) || Level.WARNING.equals(level)) {
                ps = System.err;
            }

            ps.append('\t').println(message);
            if (t != null) {
                ps.append("\t\t").append(t.getClass().getSimpleName()).append(": ").println(t.getMessage());
            }
        }
    }

    @Override
    public boolean isEnabledLevel(Level level) {
        return SimplifiedLog.isLoggable(level, getLogLevel());
    }

    @Override
    public Void call() throws Exception {
        ValidateUtils.checkTrue(isOpen(), "Scanner is closed");

        Collection<String> typeNames = getKeyTypes();
        Map<String, List<KeyPair>> pairsMap = createKeyPairs(typeNames);
        /*
         * We will need to switch signature factories for each specific key type in order to force the server to send
         * ONLY that specific key, so pre-create the factories map according to the selected key types
         */
        SortedMap<String, List<NamedFactory<Signature>>> sigFactories = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Collection<String> sigTypes = GenericUtils.asSortedSet(sigFactories.comparator(), pairsMap.keySet());
        for (String kt : sigTypes) {
            List<NamedFactory<Signature>> factories = resolveSignatureFactories(kt);
            if (GenericUtils.isEmpty(factories)) {
                if (isEnabledLevel(Level.FINEST)) {
                    log(Level.FINEST, "Skip empty signature factories for " + kt);
                }
                pairsMap.remove(kt);
            } else {
                sigFactories.put(kt, factories);
            }
        }

        ValidateUtils.checkTrue(!GenericUtils.isEmpty(pairsMap), "No client key pairs");
        ValidateUtils.checkTrue(!GenericUtils.isEmpty(sigFactories), "No signature factories");

        Exception err = null;
        try {
            ValidateUtils.checkTrue(client == null, "Client still active");
            client = SshClient.setUpDefaultClient();
            client.setServerKeyVerifier(this);

            try (BufferedReader rdr = new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8))) {
                client.setUserInteraction(new UserInteraction() {
                    @Override
                    public boolean isInteractionAllowed(ClientSession session) {
                        return true;
                    }

                    @Override
                    public String[] interactive(
                            ClientSession session, String name, String instruction,
                            String lang, String[] prompt, boolean[] echo) {
                        return null;
                    }

                    @Override
                    public String getUpdatedPassword(ClientSession session, String prompt, String lang) {
                        return null;
                    }

                    @Override
                    public void serverVersionInfo(ClientSession session, List<String> lines) {
                        if (isEnabledLevel(Level.FINE) && GenericUtils.isNotEmpty(lines)) {
                            for (String l : lines) {
                                log(Level.FINE, "Server Info: " + l);
                            }
                        }
                    }

                    @Override
                    public void welcome(ClientSession session, String banner, String lang) {
                        if (isEnabledLevel(Level.FINE) && GenericUtils.isNotEmpty(banner)) {
                            String[] lines = GenericUtils.split(banner, '\n');
                            for (String l : lines) {
                                log(Level.FINE, "Welcome[" + lang + "]: " + l);
                            }
                        }
                    }
                });

                client.start();
                for (String line = rdr.readLine(); line != null; line = rdr.readLine()) {
                    line = GenericUtils.replaceWhitespaceAndTrim(line);

                    String[] hosts = GenericUtils.split(line, ',');
                    if (GenericUtils.isEmpty(hosts)) {
                        continue;
                    }

                    for (String h : hosts) {
                        if (!isOpen()) {
                            throw new InterruptedIOException("Closed while preparing to contact host=" + h);
                        }

                        try {
                            resolveServerKeys(client, h, pairsMap, sigFactories);
                        } catch (Exception e) {
                            // check if interrupted while scanning host keys
                            if (e instanceof InterruptedIOException) {
                                throw e;
                            }

                            if (isEnabledLevel(Level.FINE)) {
                                log(Level.FINE, "Failed to retrieve keys from " + h, e);
                            }
                            err = GenericUtils.accumulateException(err, e);
                        } finally {
                            currentHostFingerprints.clear();
                        }
                    }
                }
            }
        } finally {
            try {
                close();
            } catch (IOException e) {
                err = GenericUtils.accumulateException(err, e);
            }
        }

        if (err != null) {
            throw err;
        }

        return null;
    }

    protected void resolveServerKeys(
            SshClient client, String host,
            Map<String, List<KeyPair>> pairsMap, Map<String, List<NamedFactory<Signature>>> sigFactories)
            throws IOException {
        // Cannot use forEach because of the potential for throwing IOException by the invoked code
        for (Map.Entry<String, List<KeyPair>> pe : pairsMap.entrySet()) {
            String kt = pe.getKey();
            if (!isOpen()) {
                throw new InterruptedIOException("Closed while attempting to retrieve key type=" + kt + " from " + host);
            }

            List<NamedFactory<Signature>> current = client.getSignatureFactories();
            try {
                /*
                 * Replace whatever factories there are right now with the specific one for the key in order to extract
                 * only the specific host key type
                 */
                List<NamedFactory<Signature>> forced = sigFactories.get(kt);
                client.setSignatureFactories(forced);
                resolveServerKeys(client, host, kt, pe.getValue());
            } catch (Exception e) {
                if (isEnabledLevel(Level.FINE)) {
                    log(Level.FINE, "Failed to resolve key=" + kt + " for " + host);
                }

                if (e instanceof ConnectException) {
                    return; // makes no sense to try again with another key type...
                }
            } finally {
                client.setSignatureFactories(current); // don't have to, but be nice...
            }
        }
    }

    protected void resolveServerKeys(SshClient client, String host, String kt, List<KeyPair> ids) throws Exception {
        int connectPort = getPort();
        if (isEnabledLevel(Level.FINE)) {
            log(Level.FINE, "Connecting to " + host + ":" + connectPort + " to retrieve key type=" + kt);
        }

        ConnectFuture future = client.connect(UUID.randomUUID().toString(), host, connectPort);
        long waitTime = getTimeout();
        if (!future.await(waitTime)) {
            throw new ConnectException(
                    "Failed to connect to " + host + ":" + connectPort
                                       + " within " + waitTime + " msec."
                                       + " to retrieve key type=" + kt);
        }

        try (ClientSession session = future.getSession()) {
            IoSession ioSession = session.getIoSession();
            SocketAddress remoteAddress = ioSession.getRemoteAddress();
            String remoteLocation = toString(remoteAddress);
            if (isEnabledLevel(Level.FINE)) {
                log(Level.FINE, "Connected to " + remoteLocation + " to retrieve key type=" + kt);
            }

            try {
                session.addSessionListener(this);
                if (isEnabledLevel(Level.FINER)) {
                    log(Level.FINER, "Authenticating with key type=" + kt + " to " + remoteLocation);
                }

                GenericUtils.forEach(ids, session::addPublicKeyIdentity);

                try {
                    // shouldn't really succeed, but do it since key exchange occurs only on auth attempt
                    session.auth().verify(waitTime);
                    log(Level.WARNING, "Unexpected authentication success using key type=" + kt + " with " + remoteLocation);
                } catch (Exception e) {
                    if (isEnabledLevel(Level.FINER)) {
                        log(Level.FINER, "Failed to authenticate using key type=" + kt + " with " + remoteLocation);
                    }
                } finally {
                    GenericUtils.forEach(ids, session::removePublicKeyIdentity);
                }
            } finally {
                session.removeSessionListener(this);
            }
        }
    }

    @Override
    public void sessionCreated(Session session) {
        logSessionEvent(session, "Created");
    }

    @Override
    public void sessionEvent(Session session, Event event) {
        logSessionEvent(session, event);
        if (isEnabledLevel(Level.FINEST) && Event.KexCompleted.equals(event)) {
            IoSession ioSession = session.getIoSession();
            SocketAddress remoteAddress = ioSession.getRemoteAddress();
            String remoteLocation = toString(remoteAddress);
            for (KexProposalOption paramType : KexProposalOption.VALUES) {
                String paramValue = session.getNegotiatedKexParameter(paramType);
                log(Level.FINEST, remoteLocation + "[" + paramType.getDescription() + "]: " + paramValue);
            }
        }
    }

    @Override
    public void sessionException(Session session, Throwable t) {
        logSessionEvent(session, t);
    }

    @Override
    public void sessionClosed(Session session) {
        logSessionEvent(session, "Closed");
    }

    @Override
    public void sessionNegotiationStart(
            Session session, Map<KexProposalOption, String> clientProposal, Map<KexProposalOption, String> serverProposal) {
        logSessionEvent(session, "sessionNegotiationStart");
        logNegotiationProposal("c2s", clientProposal);
        logNegotiationProposal("s2c", serverProposal);
    }

    protected void logNegotiationProposal(String type, Map<KexProposalOption, String> proposal) {
        if (!isEnabledLevel(Level.FINEST)) {
            return;
        }

        proposal.forEach((option, value) -> log(Level.FINEST, option.getDescription() + "[" + type + "]: " + value));
    }

    @Override
    public void sessionNegotiationEnd(
            Session session, Map<KexProposalOption, String> clientProposal,
            Map<KexProposalOption, String> serverProposal, Map<KexProposalOption, String> negotiatedOptions,
            Throwable reason) {
        if (reason == null) {
            logSessionEvent(session, "sessionNegotiationStart");
        } else {
            logSessionEvent(session, reason);
        }
    }

    protected void logSessionEvent(Session session, Object event) {
        if (isEnabledLevel(Level.FINEST)) {
            IoSession ioSession = session.getIoSession();
            SocketAddress remoteAddress = ioSession.getRemoteAddress();
            log(Level.FINEST, "Session " + toString(remoteAddress) + " event: " + event);
        }
    }

    @Override
    public boolean verifyServerKey(ClientSession sshClientSession, SocketAddress remoteAddress, PublicKey serverKey) {
        String remoteLocation = toString(remoteAddress);
        String extra = KeyUtils.getFingerPrint(serverKey);
        try {
            String keyType = KeyUtils.getKeyType(serverKey);
            String current = GenericUtils.isEmpty(keyType) ? null : currentHostFingerprints.get(keyType);
            if (Objects.equals(current, extra)) {
                if (isEnabledLevel(Level.FINER)) {
                    log(Level.FINER, "verifyServerKey(" + remoteLocation + ")[" + keyType + "] skip existing key: " + extra);
                }
            } else {
                if (isEnabledLevel(Level.FINE)) {
                    log(Level.FINE, "verifyServerKey(" + remoteLocation + ")[" + keyType + "] found new key: " + extra);
                }

                writeServerKey(remoteLocation, keyType, serverKey);

                if (!GenericUtils.isEmpty(keyType)) {
                    currentHostFingerprints.put(keyType, extra);
                }
            }
        } catch (Exception e) {
            log(Level.SEVERE, "Failed to output the public key " + extra + " from " + remoteLocation, e);
        }

        return true;
    }

    protected void writeServerKey(String remoteLocation, String keyType, PublicKey serverKey) throws Exception {
        StringBuilder sb = new StringBuilder(256).append(remoteLocation).append(' ');
        PublicKeyEntry.appendPublicKeyEntry(sb, serverKey);
        log(Level.INFO, sb);
    }

    private static String toString(SocketAddress addr) {
        if (addr == null) {
            return null;
        } else if (addr instanceof InetSocketAddress) {
            return ((InetSocketAddress) addr).getHostString();
        } else if (addr instanceof SshdSocketAddress) {
            return ((SshdSocketAddress) addr).getHostName();
        } else {
            return addr.toString();
        }
    }

    protected List<NamedFactory<Signature>> resolveSignatureFactories(String keyType) throws GeneralSecurityException {
        if (isEnabledLevel(Level.FINE)) {
            log(Level.FINE, "Resolve signature factories for " + keyType);
        }

        if (BuiltinIdentities.Constants.RSA.equalsIgnoreCase(keyType)) {
            return Collections.singletonList(BuiltinSignatures.rsa);
        } else if (BuiltinIdentities.Constants.DSA.equalsIgnoreCase(keyType)) {
            return Collections.singletonList(BuiltinSignatures.dsa);
        } else if (BuiltinIdentities.Constants.ECDSA.equalsIgnoreCase(keyType)) {
            List<NamedFactory<Signature>> factories = new ArrayList<>(ECCurves.NAMES.size());
            for (String n : ECCurves.NAMES) {
                if (isEnabledLevel(Level.FINER)) {
                    log(Level.FINER, "Resolve signature factory for curve=" + n);
                }

                NamedFactory<Signature> f
                        = ValidateUtils.checkNotNull(BuiltinSignatures.fromString(n), "Unknown curve signature: %s", n);
                factories.add(f);
            }

            return factories;
        } else if (BuiltinIdentities.Constants.ED25519.equalsIgnoreCase(keyType)) {
            return Collections.singletonList(BuiltinSignatures.ed25519);
        } else {
            throw new NoSuchAlgorithmException("Unknown key type: " + keyType);
        }
    }

    protected Map<String, List<KeyPair>> createKeyPairs(Collection<String> typeNames) throws GeneralSecurityException {
        if (GenericUtils.isEmpty(typeNames)) {
            return Collections.emptyMap();
        }

        Map<String, List<KeyPair>> pairsMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (String kt : typeNames) {
            if ("*".equalsIgnoreCase(kt) || "all".equalsIgnoreCase(kt)) {
                ValidateUtils.checkTrue(typeNames.size() == 1, "Wildcard key type must be the only one specified: %s",
                        typeNames);
                return createKeyPairs(BuiltinIdentities.NAMES);
            }

            if (pairsMap.containsKey(kt)) {
                log(Level.WARNING, "Key type " + kt + " re-specified");
                continue;
            }

            List<KeyPair> kps = createKeyPairs(kt);
            if (GenericUtils.isEmpty(kps)) {
                log(Level.WARNING, "No key-pairs generated for key type " + kt);
                continue;
            }

            pairsMap.put(kt, kps);
        }

        return pairsMap;
    }

    protected List<KeyPair> createKeyPairs(String keyType) throws GeneralSecurityException {
        if (isEnabledLevel(Level.FINE)) {
            log(Level.FINE, "Generate key pairs for " + keyType);
        }

        if (BuiltinIdentities.Constants.RSA.equalsIgnoreCase(keyType)) {
            return Collections.singletonList(KeyUtils.generateKeyPair(KeyPairProvider.SSH_RSA, 1024));
        } else if (BuiltinIdentities.Constants.DSA.equalsIgnoreCase(keyType)) {
            return Collections.singletonList(KeyUtils.generateKeyPair(KeyPairProvider.SSH_DSS, 512));
        } else if (BuiltinIdentities.Constants.ECDSA.equalsIgnoreCase(keyType)) {
            if (!SecurityUtils.isECCSupported()) {
                throw new NoSuchAlgorithmException("ECC not supported: " + keyType);
            }

            List<KeyPair> kps = new ArrayList<>(ECCurves.NAMES.size());
            for (ECCurves curve : ECCurves.VALUES) {
                String curveName = curve.getName();
                if (isEnabledLevel(Level.FINER)) {
                    log(Level.FINER, "Generate key pair for curve=" + curveName);
                }

                kps.add(KeyUtils.generateKeyPair(curve.getKeyType(), curve.getKeySize()));
            }

            return kps;
        } else if (BuiltinIdentities.Constants.ED25519.equalsIgnoreCase(keyType)) {
            if (!SecurityUtils.isEDDSACurveSupported()) {
                throw new NoSuchAlgorithmException("EDDSA curves not supported: " + keyType);
            }

            KeyPairGenerator g = SecurityUtils.getKeyPairGenerator(SecurityUtils.EDDSA);
            return Collections.singletonList(g.generateKeyPair());
        } else {
            throw new InvalidKeySpecException("Unknown key type: " + keyType);
        }
    }

    @Override
    public boolean isOpen() {
        return open.get();
    }

    @Override
    public void close() throws IOException {
        if (!open.getAndSet(false)) {
            return; // already closed
        }

        IOException err = null;
        if (input != null) {
            try {
                input.close();
            } catch (IOException e) {
                err = GenericUtils.accumulateException(err, e);
            } finally {
                input = null;
            }
        }

        if (client != null) {
            try {
                client.close();
            } catch (IOException e) {
                err = GenericUtils.accumulateException(err, e);
            } finally {
                try {
                    client.stop();
                } finally {
                    client = null;
                }
            }
        }
        if (err != null) {
            throw err;
        }
    }

    //////////////////////////////////////////////////////////////////////////

    // returns a List of the hosts to be contacted
    public static List<String> parseCommandLineArguments(SshKeyScanMain scanner, String... args) throws IOException {
        int numArgs = GenericUtils.length(args);
        for (int index = 0; index < numArgs; index++) {
            String optName = args[index];
            if ("-f".equals(optName)) {
                index++;
                ValidateUtils.checkTrue(index < numArgs, "Missing %s option argument", optName);
                ValidateUtils.checkTrue(scanner.getInputStream() == null, "%s option re-specified", optName);

                String filePath = args[index];
                if ("-".equals(filePath)) {
                    scanner.setInputStream(new NoCloseInputStream(System.in));
                } else {
                    scanner.setInputStream(new FileInputStream(filePath));
                }
            } else if ("-t".equals(optName)) {
                index++;
                ValidateUtils.checkTrue(index < numArgs, "Missing %s option argument", optName);
                ValidateUtils.checkTrue(GenericUtils.isEmpty(scanner.getKeyTypes()), "%s option re-specified", optName);

                String typeList = args[index];
                String[] types = GenericUtils.split(typeList, ',');
                ValidateUtils.checkTrue(GenericUtils.length(types) > 0, "No types specified for %s", optName);
                scanner.setKeyTypes(Arrays.asList(types));
            } else if ("-p".equals(optName)) {
                index++;
                ValidateUtils.checkTrue(index < numArgs, "Missing %s option argument", optName);
                ValidateUtils.checkTrue(scanner.getPort() <= 0, "%s option re-specified", optName);

                String portValue = args[index];
                int port = Integer.parseInt(portValue);
                ValidateUtils.checkTrue((port > 0) && (port <= 0xFFFF), "Bad port: %s", portValue);
                scanner.setPort(port);
            } else if ("-T".equals(optName)) {
                index++;
                ValidateUtils.checkTrue(index < numArgs, "Missing %s option argument", optName);
                ValidateUtils.checkTrue(scanner.getTimeout() <= 0, "%s option re-specified", optName);

                String timeoutValue = args[index];
                long timeout = Long.parseLong(timeoutValue);
                ValidateUtils.checkTrue(timeout > 0L, "Bad timeout: %s", timeoutValue);
                scanner.setTimeout(timeout);
            } else if ("-v".equals(optName)) {
                ValidateUtils.checkTrue(scanner.getLogLevel() == null, "%s option re-specified", optName);
                scanner.setLogLevel(Level.FINEST);
            } else if ("-io".equals(optName)) {
                if ((index + 1) >= numArgs) {
                    System.err.println("option requires an argument: " + optName);
                    break;
                }

                String provider = args[++index];
                BuiltinIoServiceFactoryFactories factory
                        = CliSupport.resolveBuiltinIoServiceFactory(System.err, optName, provider);
                if (factory != null) {
                    System.setProperty(IoServiceFactory.class.getName(), factory.getFactoryClassName());
                } else {
                    break;
                }
            } else { // stop at first non-option - assume the rest are host names/addresses
                ValidateUtils.checkTrue(optName.charAt(0) != '-', "Unknown option: %s", optName);

                int remaining = numArgs - index;
                if (remaining == 1) {
                    return Collections.singletonList(optName);
                }

                List<String> hosts = new ArrayList<>(remaining);
                for (; index < numArgs; index++) {
                    hosts.add(args[index]);
                }

                return hosts;
            }
        }

        return Collections.emptyList();
    }

    /* -------------------------------------------------------------------- */

    public static <S extends SshKeyScanMain> S setInputStream(S scanner, Collection<String> hosts) throws IOException {
        if (GenericUtils.isEmpty(hosts)) {
            Objects.requireNonNull(scanner.getInputStream(), "No hosts or file specified");
        } else {
            ValidateUtils.checkTrue(scanner.getInputStream() == null, "Both hosts and file specified");

            // convert the hosts from the arguments into a "file" - one host per line
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream(hosts.size() * 32)) {
                try (Writer w = new OutputStreamWriter(baos, StandardCharsets.UTF_8)) {
                    for (String h : hosts) {
                        w.append(h).append(IoUtils.EOL);
                    }
                }

                byte[] data = baos.toByteArray();
                scanner.setInputStream(new ByteArrayInputStream(data));
            }
        }

        return scanner;
    }

    public static <S extends SshKeyScanMain> S initializeScanner(S scanner, Collection<String> hosts) throws IOException {
        setInputStream(scanner, hosts);
        if (scanner.getPort() <= 0) {
            scanner.setPort(SshConstants.DEFAULT_PORT);
        }

        if (scanner.getTimeout() <= 0L) {
            scanner.setTimeout(DEFAULT_TIMEOUT);
        }

        if (GenericUtils.isEmpty(scanner.getKeyTypes())) {
            scanner.setKeyTypes(DEFAULT_KEY_TYPES);
        }

        if (scanner.getLogLevel() == null) {
            scanner.setLogLevel(DEFAULT_LEVEL);
        }

        return scanner;
    }

    /* -------------------------------------------------------------------- */

    public static void main(String[] args) throws Exception {
        try (SshKeyScanMain scanner = new SshKeyScanMain()) {
            Collection<String> hosts = parseCommandLineArguments(scanner, args);
            initializeScanner(scanner, hosts);
            scanner.call();
        }
    }
}
