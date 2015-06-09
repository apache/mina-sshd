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

package org.apache.sshd.client;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.Writer;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshdSocketAddress;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.SshConfigFileReader;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.common.util.logging.AbstractSimplifiedLog;
import org.apache.sshd.common.util.logging.LoggingUtils;

/**
 * A naive implementation of <A HREF="https://www.freebsd.org/cgi/man.cgi?query=ssh-keyscan&sektion=1">ssh-keyscan(1)</A>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshKeyScan extends AbstractSimplifiedLog
                        implements Closeable, Callable<Void>, ServerKeyVerifier, SessionListener {
    /**
     * Default key types if not overridden from the command line
     */
    public static final List<String> DEFAULT_KEY_TYPES =
            Collections.unmodifiableList(Arrays.asList("rsa", "ecdsa"));
    public static final long DEFAULT_TIMEOUT = TimeUnit.SECONDS.toMillis(5L);
    public static final Level DEFAULT_LEVEL = Level.INFO;

    private int port;
    private long timeout;
    private List<String> keyTypes;
    private InputStream input;
    private Level level;
    private final Map<String,String> currentHostFingerprints = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);

    public SshKeyScan() {
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
        if (isEnabled(level)) {
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
    public boolean isEnabled(Level level) {
        return LoggingUtils.isLoggable(level, getLogLevel());
    }

    @Override
    public Void call() throws Exception {
        Exception err = null;
        try(SshClient   client = SshClient.setUpDefaultClient()) {
            Collection<String> typeNames = getKeyTypes();
            Map<String,KeyPair> pairsMap = createKeyPairs(typeNames);
            client.setServerKeyVerifier(this);

            try(BufferedReader rdr = new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8))) {
                client.start();

                for (String line = rdr.readLine(); line != null; line = rdr.readLine()) {
                    line = GenericUtils.trimToEmpty(line);
                    if (GenericUtils.isEmpty(line)) {
                        continue;
                    }
                    
                    try {
                        resolveServerKeys(client, line, pairsMap);
                    } catch(Exception e) {
                        if (isEnabled(Level.FINE)) {
                            log(Level.FINE, "Failed to retrieve keys from " + line, e);
                        }
                        err = GenericUtils.accumulateException(err, e);
                    } finally {
                        currentHostFingerprints.clear();
                    }
                }
            } finally {
                client.stop();
            }
        }
        
        if (err != null) {
            throw err;
        }

        return null;
    }

    protected void resolveServerKeys(SshClient client, String host, Map<String,KeyPair> pairsMap) {
        for (Map.Entry<String,KeyPair> pe : pairsMap.entrySet()) {
            String kt = pe.getKey();
            try {
                resolveServerKeys(client, host, kt, pe.getValue());
            } catch(Exception e) {
                if (isEnabled(Level.FINE)) {
                    log(Level.FINE, "Failed to resolve key=" + kt + " for " + host);
                }
                
                if (e instanceof ConnectException) {
                    return; // makes no sense to try again with another key type...
                }
            }
        }
    }
    
    protected void resolveServerKeys(SshClient client, String host, String kt, KeyPair kp) throws Exception {
        int connectPort = getPort();
        if (isEnabled(Level.FINE)) {
            log(Level.FINE, "Connecting to " + host + ":" + connectPort);
        }

        ConnectFuture future = client.connect(UUID.randomUUID().toString(), host, connectPort);
        long waitTime = getTimeout();
        if (!future.await(waitTime)) {
            throw new ConnectException("Failed to connect to " + host + ":" + connectPort + " within " + waitTime + " msec.");
        }

        try(ClientSession session = future.getSession()) {
            IoSession ioSession = session.getIoSession();
            SocketAddress remoteAddress = ioSession.getRemoteAddress();
            String remoteLocation = toString(remoteAddress);
            if (isEnabled(Level.FINE)) {
                log(Level.FINE, "Connected to " + remoteLocation);
            }

            try {
                session.addListener(this);
                if (isEnabled(Level.FINER)) {
                    log(Level.FINER, "Authenticating with " + kt + " to " + remoteLocation);
                }

                // shouldn't really succeed, but do it since key exchange occurs only on auth attempt
                session.addPublicKeyIdentity(kp);
                try {
                    session.auth().verify(waitTime);
                    log(Level.WARNING, "Unexpected authentication success using key type=" + kt + " with " + remoteLocation);
                } catch(Exception e) {
                    if (isEnabled(Level.FINER)) {
                        log(Level.FINER, "Failed to authenticate using key type=" + kt + " with " + remoteLocation);
                    }
                }
            } finally {
                session.removeListener(this);
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
        if (isEnabled(Level.FINEST) && Event.KexCompleted.equals(event)) {
            IoSession ioSession = session.getIoSession();
            SocketAddress remoteAddress = ioSession.getRemoteAddress();
            String remoteLocation = toString(remoteAddress);
            for (int paramType = 0; paramType < SshConstants.PROPOSAL_KEX_NAMES.size(); paramType++) {
                String paramName = SshConstants.PROPOSAL_KEX_NAMES.get(paramType);
                String paramValue = session.getNegotiatedKexParameter(paramType);
                log(Level.FINEST, remoteLocation + "[" + paramName + "]: " + paramValue);
            }
        }
    }

    @Override
    public void sessionClosed(Session session) {
        logSessionEvent(session, "Closed");
    }

    protected void logSessionEvent(Session session, Object event) {
        if (isEnabled(Level.FINEST)) {
            IoSession ioSession = session.getIoSession();
            SocketAddress remoteAddress = ioSession.getRemoteAddress();
            log(Level.FINEST, "Session " + toString(remoteAddress) + " event: " + event);
        }
    }

    @Override
    public boolean verifyServerKey(ClientSession sshClientSession, SocketAddress remoteAddress, PublicKey serverKey) {
        String remoteLocation = toString(remoteAddress);
        try {
            String extra = KeyUtils.getFingerPrint(serverKey);
            String keyType = KeyUtils.getKeyType(serverKey);
            String current = GenericUtils.isEmpty(keyType) ? null : currentHostFingerprints.get(keyType);
            if (Objects.equals(current, extra)) {
                if (isEnabled(Level.FINER)) {
                    log(Level.FINER, "verifyServerKey(" + remoteLocation + ")[" + keyType + "] skip existing key: " + extra);
                }
            } else {
                if (isEnabled(Level.FINE)) {
                    log(Level.FINE, "verifyServerKey(" + remoteLocation + ")[" + keyType + "] found new key: " + extra);
                }

                StringBuilder   sb = new StringBuilder(256).append(remoteLocation).append(' ');
                PublicKeyEntry.appendPublicKeyEntry(sb, serverKey);
                log(Level.INFO, sb);
                
                if (!GenericUtils.isEmpty(keyType)) {
                    currentHostFingerprints.put(keyType, extra);
                }
            }
        } catch(Exception e) {
            log(Level.SEVERE, "Failed to output the public key from " + remoteLocation, e);
        }

        return true;
    }

    private static final String toString(SocketAddress addr) {
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

    protected Map<String,KeyPair> createKeyPairs(Collection<String> typeNames) throws GeneralSecurityException {
        if (GenericUtils.isEmpty(typeNames)) {
            return Collections.emptyMap();
        }

        Map<String,KeyPair> pairsMap = new TreeMap<String, KeyPair>(String.CASE_INSENSITIVE_ORDER);
        for (String kt : typeNames) {
            if (isEnabled(Level.FINE)) {
                log(Level.FINE, "Generate key pair for " + kt);
            }

            if ("rsa".equalsIgnoreCase(kt)) {
                pairsMap.put(KeyPairProvider.SSH_RSA, KeyUtils.generateKeyPair(KeyPairProvider.SSH_RSA, 1024));
            } else if ("dsa".equalsIgnoreCase(kt)) {
                pairsMap.put(KeyPairProvider.SSH_DSS, KeyUtils.generateKeyPair(KeyPairProvider.SSH_DSS, 512));
            } else if ("ecdsa".equalsIgnoreCase(kt)) {
                if (!SecurityUtils.hasEcc()) {
                    throw new InvalidKeySpecException("ECC not supported");
                }

                for (String curveName : ECCurves.NAMES) {
                    Integer keySize = ECCurves.getCurveSize(curveName);
                    if (keySize == null) {
                        throw new InvalidKeySpecException("Unknown curve: " + curveName);
                    }

                    if (isEnabled(Level.FINER)) {
                        log(Level.FINER, "Generate key pair for curve=" + curveName);
                    }

                    String keyName = ECCurves.ECDSA_SHA2_PREFIX + curveName;
                    pairsMap.put(keyName, KeyUtils.generateKeyPair(keyName, keySize.intValue()));
                }
            }
        }
        
        return pairsMap;
    }

    @Override
    public void close() throws IOException {
        IOException err = null;
        if (input != null) {
            try {
                input.close();
            } catch(IOException e) {
                err = GenericUtils.accumulateException(err, e);
            } finally {
                input = null;
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////

    // returns a List of the hosts to be contacted
    public static final List<String> parseCommandLineArguments(SshKeyScan scanner, String ... args) throws IOException {
        int numArgs = GenericUtils.length(args);
        for (int index=0; index < numArgs; index++) {
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
            } else {    // stop at first non-option - assume the rest are host names/addresses
                ValidateUtils.checkTrue((optName.charAt(0) != '-'), "Unknown option: %s", optName);
                
                int remaining = numArgs - index;
                if (remaining == 1) {
                    return Collections.singletonList(optName);
                }
                
                List<String> hosts = new ArrayList<String>(remaining);
                for ( ; index < numArgs; index++) {
                    hosts.add(args[index]);
                }
                
                return hosts;
            }
        }
        
        return Collections.emptyList();
    }

    /* -------------------------------------------------------------------- */

    public static final <S extends SshKeyScan> S setInputStream(S scanner, Collection<String> hosts) throws IOException {
        if (GenericUtils.isEmpty(hosts)) {
            ValidateUtils.checkNotNull(scanner.getInputStream(), "No hosts or file specified", GenericUtils.EMPTY_OBJECT_ARRAY);
        } else {
            ValidateUtils.checkTrue(scanner.getInputStream() == null, "Both hosts and file specified", GenericUtils.EMPTY_OBJECT_ARRAY);
            
            // convert the hosts from the arguments into a "file" - one host per line
            try(ByteArrayOutputStream baos = new ByteArrayOutputStream(hosts.size() * 32)) {
                try(Writer w = new OutputStreamWriter(baos, StandardCharsets.UTF_8)) {
                    String EOL = System.getProperty("line.separator");
                    for (String h : hosts) {
                        w.append(h).append(EOL);
                    }
                }
                
                byte[] data = baos.toByteArray();
                scanner.setInputStream(new ByteArrayInputStream(data));
            }
        }
        
        return scanner;
    }

    public static final <S extends SshKeyScan> S initializeScanner(S scanner, Collection<String> hosts) throws IOException {
        setInputStream(scanner, hosts);
        if (scanner.getPort() <= 0) {
            scanner.setPort(SshConfigFileReader.DEFAULT_PORT);
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
        try(SshKeyScan scanner = new SshKeyScan()) {
            Collection<String> hosts = parseCommandLineArguments(scanner, args);
            initializeScanner(scanner, hosts);
            scanner.call();
        }
    }
}
