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
package org.apache.sshd;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.ServerKeyVerifier;
import org.apache.sshd.client.SessionFactory;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.UserInteraction;
import org.apache.sshd.client.auth.UserAuthKeyboardInteractive;
import org.apache.sshd.client.auth.UserAuthPassword;
import org.apache.sshd.client.auth.UserAuthPublicKey;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.future.DefaultConnectFuture;
import org.apache.sshd.client.kex.DHG1;
import org.apache.sshd.client.kex.DHG14;
import org.apache.sshd.client.kex.DHGEX;
import org.apache.sshd.client.kex.DHGEX256;
import org.apache.sshd.client.kex.ECDHP256;
import org.apache.sshd.client.kex.ECDHP384;
import org.apache.sshd.client.kex.ECDHP521;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.client.session.ClientConnectionService;
import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.sshd.client.session.ClientUserAuthService;
import org.apache.sshd.common.AbstractFactoryManager;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.Cipher;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.Compression;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.KeyExchange;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.Mac;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Signature;
import org.apache.sshd.common.cipher.AES128CBC;
import org.apache.sshd.common.cipher.AES128CTR;
import org.apache.sshd.common.cipher.AES192CBC;
import org.apache.sshd.common.cipher.AES256CBC;
import org.apache.sshd.common.cipher.AES256CTR;
import org.apache.sshd.common.cipher.ARCFOUR128;
import org.apache.sshd.common.cipher.ARCFOUR256;
import org.apache.sshd.common.cipher.BlowfishCBC;
import org.apache.sshd.common.cipher.TripleDESCBC;
import org.apache.sshd.common.compression.CompressionNone;
import org.apache.sshd.common.file.nativefs.NativeFileSystemFactory;
import org.apache.sshd.common.forward.DefaultTcpipForwarderFactory;
import org.apache.sshd.common.forward.TcpipServerChannel;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.DefaultIoServiceFactoryFactory;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoConnector;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.mac.HMACMD5;
import org.apache.sshd.common.mac.HMACMD596;
import org.apache.sshd.common.mac.HMACSHA1;
import org.apache.sshd.common.mac.HMACSHA196;
import org.apache.sshd.common.mac.HMACSHA256;
import org.apache.sshd.common.mac.HMACSHA512;
import org.apache.sshd.common.random.BouncyCastleRandom;
import org.apache.sshd.common.random.JceRandom;
import org.apache.sshd.common.random.SingletonRandomFactory;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.signature.SignatureDSA;
import org.apache.sshd.common.signature.SignatureECDSA;
import org.apache.sshd.common.signature.SignatureRSA;
import org.apache.sshd.common.util.CloseableUtils;
import org.apache.sshd.common.util.NoCloseInputStream;
import org.apache.sshd.common.util.NoCloseOutputStream;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.ThreadUtils;
import org.bouncycastle.openssl.PasswordFinder;

/**
 * Entry point for the client side of the SSH protocol.
 *
 * The default configured client can be created using
 * the {@link #setUpDefaultClient()}.  The next step is to
 * start the client using the {@link #start()} method.
 *
 * Sessions can then be created using on of the
 * {@link #connect(String, int)} or {@link #connect(java.net.SocketAddress)}
 * methods.
 *
 * The client can be stopped at anytime using the {@link #stop()} method.
 *
 * Following is an example of using the SshClient:
 * <pre>
 *    SshClient client = SshClient.setUpDefaultClient();
 *    client.start();
 *    try {
 *        ClientSession session = client.connect(host, port).await().getSession();
 *
 *        int ret = ClientSession.WAIT_AUTH;
 *        while ((ret & ClientSession.WAIT_AUTH) != 0) {
 *            System.out.print("Password:");
 *            BufferedReader r = new BufferedReader(new InputStreamReader(System.in));
 *            String password = r.readLine();
 *            session.authPassword(login, password);
 *            ret = session.waitFor(ClientSession.WAIT_AUTH | ClientSession.CLOSED | ClientSession.AUTHED, 0);
 *        }
 *        if ((ret & ClientSession.CLOSED) != 0) {
 *            System.err.println("error");
 *            System.exit(-1);
 *        }
 *        ClientChannel channel = session.createChannel("shell");
 *        channel.setIn(new NoCloseInputStream(System.in));
 *        channel.setOut(new NoCloseOutputStream(System.out));
 *        channel.setErr(new NoCloseOutputStream(System.err));
 *        channel.open();
 *        channel.waitFor(ClientChannel.CLOSED, 0);
 *        session.close(false);
 *    } finally {
 *        client.stop();
 *    }
 * </pre>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshClient extends AbstractFactoryManager implements ClientFactoryManager, Closeable {

    protected IoConnector connector;
    protected SessionFactory sessionFactory;
    protected UserInteraction userInteraction;
    protected Factory<IoConnector> connectorFactory;
    protected List<NamedFactory<UserAuth>> userAuthFactories;

    private ServerKeyVerifier serverKeyVerifier;

    public SshClient() {
    }

    public SessionFactory getSessionFactory() {
        return sessionFactory;
    }

    public void setSessionFactory(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    public ServerKeyVerifier getServerKeyVerifier() {
        return serverKeyVerifier;
    }

    public void setServerKeyVerifier(ServerKeyVerifier serverKeyVerifier) {
        this.serverKeyVerifier = serverKeyVerifier;
    }

    public UserInteraction getUserInteraction() {
        return userInteraction;
    }

    public void setUserInteraction(UserInteraction userInteraction) {
        this.userInteraction = userInteraction;
    }

    public List<NamedFactory<UserAuth>> getUserAuthFactories() {
        return userAuthFactories;
    }

    public void setUserAuthFactories(List<NamedFactory<UserAuth>> userAuthFactories) {
        this.userAuthFactories = userAuthFactories;
    }

    protected void checkConfig() {
        if (getKeyExchangeFactories() == null) {
            throw new IllegalArgumentException("KeyExchangeFactories not set");
        }
        if (getScheduledExecutorService() == null) {
            setScheduledExecutorService(
                    ThreadUtils.newSingleThreadScheduledExecutor(this.toString() + "-timer"),
                    true);
        }
        if (getCipherFactories() == null) {
            throw new IllegalArgumentException("CipherFactories not set");
        }
        if (getCompressionFactories() == null) {
            throw new IllegalArgumentException("CompressionFactories not set");
        }
        if (getMacFactories() == null) {
            throw new IllegalArgumentException("MacFactories not set");
        }
        if (getRandomFactory() == null) {
            throw new IllegalArgumentException("RandomFactory not set");
        }
        if (getTcpipForwarderFactory() == null) {
            throw new IllegalArgumentException("TcpipForwarderFactory not set");
        }
        if (getServerKeyVerifier() == null) {
            throw new IllegalArgumentException("ServerKeyVerifier not set");
        }
        // Register the additional agent forwarding channel if needed
        if (getAgentFactory() != null) {
            List<NamedFactory<Channel>> factories = getChannelFactories();
            if (factories == null) {
                factories = new ArrayList<NamedFactory<Channel>>();
            } else {
                factories = new ArrayList<NamedFactory<Channel>>(factories);
            }
            factories.add(getAgentFactory().getChannelForwardingFactory());
            setChannelFactories(factories);
        }
        if (getIoServiceFactoryFactory() == null) {
            setIoServiceFactoryFactory(new DefaultIoServiceFactoryFactory());
        }
        if (getServiceFactories() == null) {
            setServiceFactories(Arrays.asList(
                    new ClientUserAuthService.Factory(),
                    new ClientConnectionService.Factory()
            ));
        }
        if (getUserAuthFactories() == null) {
            setUserAuthFactories(Arrays.asList(
                    new UserAuthPublicKey.Factory(),
                    new UserAuthKeyboardInteractive.Factory(),
                    new UserAuthPassword.Factory()
            ));
        }
    }

    public void start() {
        checkConfig();
        if (sessionFactory == null) {
            sessionFactory = createSessionFactory();
        }
        sessionFactory.setClient(this);
        connector = createConnector();
    }

    public void stop() {
        try {
            close(true).await();
        } catch (InterruptedException e) {
            log.debug("Exception caught while stopping client", e);
        }
    }

    public void open() throws IOException {
        start();
    }

    public CloseFuture close(boolean immediately) {
        CloseFuture future;
        if (connector != null) {
            future = CloseableUtils.sequential(connector, ioServiceFactory).close(immediately);
        } else if (ioServiceFactory != null) {
            future = ioServiceFactory.close(immediately);
        } else {
            future = CloseableUtils.closed();
        }
        future.addListener(new SshFutureListener<CloseFuture>() {
            public void operationComplete(CloseFuture future) {
                connector = null;
                ioServiceFactory = null;
                if (shutdownExecutor && executor != null) {
                    executor.shutdown();
                    executor = null;
                }
            }
        });
        return future;
    }

    @Deprecated
    public ConnectFuture connect(String host, int port) throws IOException {
        return connect(null, host, port);
    }

    public ConnectFuture connect(String username, String host, int port) throws IOException {
        assert host != null;
        assert port >= 0;
        if (connector == null) {
            throw new IllegalStateException("SshClient not started. Please call start() method before connecting to a server");
        }
        SocketAddress address = new InetSocketAddress(host, port);
        return connect(username, address);
    }

    @Deprecated
    public ConnectFuture connect(SocketAddress address) {
        return connect(null, address);
    }

    public ConnectFuture connect(final String username, SocketAddress address) {
        assert address != null;
        if (connector == null) {
            throw new IllegalStateException("SshClient not started. Please call start() method before connecting to a server");
        }
        final ConnectFuture connectFuture = new DefaultConnectFuture(null);
        connector.connect(address).addListener(new SshFutureListener<IoConnectFuture>() {
            public void operationComplete(IoConnectFuture future) {
                if (future.isCanceled()) {
                    connectFuture.cancel();
                } else if (future.getException() != null) {
                    connectFuture.setException(future.getException());
                } else {
                    ClientSessionImpl session = (ClientSessionImpl) AbstractSession.getSession(future.getSession());
                    session.setUsername(username);
                    connectFuture.setSession(session);
                }
            }
        });
        return connectFuture;
    }

    protected IoConnector createConnector() {
        return getIoServiceFactory().createConnector(getSessionFactory());
    }

    protected SessionFactory createSessionFactory() {
        return new SessionFactory();
    }

    @Override
    public String toString() {
        return "SshClient[" + Integer.toHexString(hashCode()) + "]";
    }

    /**
     * Setup a default client.  The client does not require any additional setup.
     *
     * @return a newly create SSH client
     */
    public static SshClient setUpDefaultClient() {
        SshClient client = new SshClient();
        // DHG14 uses 2048 bits key which are not supported by the default JCE provider
        if (SecurityUtils.isBouncyCastleRegistered()) {
            client.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>>asList(
                    new DHGEX256.Factory(),
                    new DHGEX.Factory(),
                    new ECDHP256.Factory(),
                    new ECDHP384.Factory(),
                    new ECDHP521.Factory(),
                    new DHG14.Factory(),
                    new DHG1.Factory()));
            client.setSignatureFactories(Arrays.<NamedFactory<Signature>>asList(
                    new SignatureDSA.Factory(),
                    new SignatureRSA.Factory(),
                    new SignatureECDSA.NISTP256Factory(),
                    new SignatureECDSA.NISTP384Factory(),
                    new SignatureECDSA.NISTP521Factory()));
            client.setRandomFactory(new SingletonRandomFactory(new BouncyCastleRandom.Factory()));
        // EC keys are not supported until OpenJDK 7
        } else if (SecurityUtils.hasEcc()) {
            client.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>>asList(
                    new ECDHP256.Factory(),
                    new ECDHP384.Factory(),
                    new ECDHP521.Factory(),
                    new DHG1.Factory()));
            client.setSignatureFactories(Arrays.<NamedFactory<Signature>>asList(
                    new SignatureDSA.Factory(),
                    new SignatureRSA.Factory(),
                    new SignatureECDSA.NISTP256Factory(),
                    new SignatureECDSA.NISTP384Factory(),
                    new SignatureECDSA.NISTP521Factory()));
            client.setRandomFactory(new SingletonRandomFactory(new JceRandom.Factory()));
        } else {
            client.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>>asList(
                    new DHG1.Factory()));
            client.setSignatureFactories(Arrays.<NamedFactory<Signature>>asList(
                    new SignatureDSA.Factory(),
                    new SignatureRSA.Factory()));
            client.setRandomFactory(new SingletonRandomFactory(new JceRandom.Factory()));
        }
        setUpDefaultCiphers(client);
        // Compression is not enabled by default
        // client.setCompressionFactories(Arrays.<NamedFactory<Compression>>asList(
        //         new CompressionNone.Factory(),
        //         new CompressionZlib.Factory(),
        //         new CompressionDelayedZlib.Factory()));
        client.setCompressionFactories(Arrays.<NamedFactory<Compression>>asList(
                new CompressionNone.Factory()));
        client.setMacFactories(Arrays.<NamedFactory<Mac>>asList(
                new HMACSHA256.Factory(),
                new HMACSHA512.Factory(),
                new HMACSHA1.Factory(),
                new HMACMD5.Factory(),
                new HMACSHA196.Factory(),
                new HMACMD596.Factory()));
        client.setChannelFactories(Arrays.<NamedFactory<Channel>>asList(
                new TcpipServerChannel.ForwardedTcpipFactory()));
        client.setServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);
        client.setFileSystemFactory(new NativeFileSystemFactory());
        client.setTcpipForwarderFactory(new DefaultTcpipForwarderFactory());
        return client;
    }

    private static void setUpDefaultCiphers(SshClient client) {
        List<NamedFactory<Cipher>> avail = new LinkedList<NamedFactory<Cipher>>();
        avail.add(new AES128CTR.Factory());
        avail.add(new AES256CTR.Factory());
        avail.add(new ARCFOUR128.Factory());
        avail.add(new ARCFOUR256.Factory());
        avail.add(new AES128CBC.Factory());
        avail.add(new TripleDESCBC.Factory());
        avail.add(new BlowfishCBC.Factory());
        avail.add(new AES192CBC.Factory());
        avail.add(new AES256CBC.Factory());

        for (Iterator<NamedFactory<Cipher>> i = avail.iterator(); i.hasNext();) {
            final NamedFactory<Cipher> f = i.next();
            try {
                final Cipher c = f.create();
                final byte[] key = new byte[c.getBlockSize()];
                final byte[] iv = new byte[c.getIVSize()];
                c.init(Cipher.Mode.Encrypt, key, iv);
            } catch (InvalidKeyException e) {
                i.remove();
            } catch (Exception e) {
                i.remove();
            }
        }
        client.setCipherFactories(avail);
    }

    /*=================================
          Main class implementation
     *=================================*/

    public static void main(String[] args) throws Exception {
        Handler fh = new ConsoleHandler();
        fh.setLevel(Level.FINEST);
        fh.setFormatter(new Formatter() {
            @Override
            public String format(LogRecord record) {
                String message = formatMessage(record);
                String throwable = "";
                if (record.getThrown() != null) {
                    StringWriter sw = new StringWriter();
                    PrintWriter pw = new PrintWriter(sw);
                    pw.println();
                    record.getThrown().printStackTrace(pw);
                    pw.close();
                    throwable = sw.toString();
                }
                return String.format("%1$tY-%1$tm-%1$td: %2$-7.7s: %3$-32.32s: %4$s%5$s%n",
                        new Date(record.getMillis()),
                        record.getLevel().getName(),
                        record.getLoggerName(),
                        message,
                        throwable);
            }
        });
        Logger root = Logger.getLogger("");
        for (Handler handler : root.getHandlers()) {
            root.removeHandler(handler);
        }
        root.addHandler(fh);

        int port = 22;
        String host = null;
        String login = System.getProperty("user.name");
        boolean agentForward = false;
        List<String> command = null;
        int logLevel = 0;
        boolean error = false;
        List<String> identities = new ArrayList<String>();

        for (int i = 0; i < args.length; i++) {
            if (command == null && "-p".equals(args[i])) {
                if (i + 1 >= args.length) {
                    System.err.println("option requires an argument: " + args[i]);
                    error = true;
                    break;
                }
                port = Integer.parseInt(args[++i]);
            } else if (command == null && "-l".equals(args[i])) {
                if (i + 1 >= args.length) {
                    System.err.println("option requires an argument: " + args[i]);
                    error = true;
                    break;
                }
                login = args[++i];
            } else if (command == null && "-v".equals(args[i])) {
                logLevel += 1;
            } else if (command == null && "-vv".equals(args[i])) {
                logLevel += 2;
            } else if (command == null && "-vvv".equals(args[i])) {
                logLevel += 3;
            } else if ("-A".equals(args[i])) {
                agentForward = true;
            } else if ("-a".equals(args[i])) {
                agentForward = false;
            } else if ("-i".equals(args[i])) {
                if (i + 1 >= args.length) {
                    System.err.println("option requires and argument: " + args[i]);
                    error = true;
                    break;
                }
                identities.add(args[++i]);
            } else if (command == null && args[i].startsWith("-")) {
                System.err.println("illegal option: " + args[i]);
                error = true;
                break;
            } else {
                if (host == null) {
                    host = args[i];
                } else {
                    if (command == null) {
                        command = new ArrayList<String>();
                    }
                    command.add(args[i]);
                }
            }
        }
        if (host == null) {
            System.err.println("hostname required");
            error = true;
        }
        if (error) {
            System.err.println("usage: ssh [-A|-a] [-v[v][v]] [-l login] [-p port] hostname [command]");
            System.exit(-1);
        }
        if (logLevel <= 0) {
            root.setLevel(Level.WARNING);
        } else if (logLevel == 1) {
            root.setLevel(Level.INFO);
        } else if (logLevel == 2) {
            root.setLevel(Level.FINE);
        } else {
            root.setLevel(Level.FINEST);
        }

        KeyPairProvider provider = null;
        final List<String> files = new ArrayList<String>();
        File f = new File(System.getProperty("user.home"), ".ssh/id_dsa");
        if (f.exists() && f.isFile() && f.canRead()) {
            files.add(f.getAbsolutePath());
        }
        f = new File(System.getProperty("user.home"), ".ssh/id_rsa");
        if (f.exists() && f.isFile() && f.canRead()) {
            files.add(f.getAbsolutePath());
        }
        if (files.size() > 0) {
            // SSHD-292: we need to use a different class to load the FileKeyPairProvider
            //  in order to break the link between SshClient and BouncyCastle
            try {
                if (SecurityUtils.isBouncyCastleRegistered()) {
                    class KeyPairProviderLoader implements Callable<KeyPairProvider> {
                        public KeyPairProvider call() throws Exception {
                            return new FileKeyPairProvider(files.toArray(new String[files.size()]), new PasswordFinder() {
                                public char[] getPassword() {
                                    try {
                                        System.out.println("Enter password for private key: ");
                                        BufferedReader r = new BufferedReader(new InputStreamReader(System.in));
                                        String password = r.readLine();
                                        return password.toCharArray();
                                    } catch (IOException e) {
                                        return null;
                                    }
                                }
                            });
                        }
                    };
                    provider = new KeyPairProviderLoader().call();
                }
            } catch (Throwable t) {
                System.out.println("Error loading user keys: " + t.getMessage());
            }
        }

        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        client.setKeyPairProvider(provider);
        client.setUserInteraction(new UserInteraction() {
            public void welcome(String banner) {
                System.out.println(banner);
            }
            public String[] interactive(String destination, String name, String instruction, String[] prompt, boolean[] echo) {
                String[] answers = new String[prompt.length];
                try {
                    for (int i = 0; i < prompt.length; i++) {
                        BufferedReader r = new BufferedReader(new InputStreamReader(System.in));
                        System.out.print(prompt[i] + " ");
                        answers[i] = r.readLine();
                    }
                } catch (IOException e) {
                }
                return answers;
            }
        });

        /*
        String authSock = System.getenv(SshAgent.SSH_AUTHSOCKET_ENV_NAME);
        if (authSock == null && provider != null) {
            Iterable<KeyPair> keys = provider.loadKeys();
            AgentServer server = new AgentServer();
            authSock = server.start();
            SshAgent agent = new AgentClient(authSock);
            for (KeyPair key : keys) {
                agent.addIdentity(key, "");
            }
            agent.close();
            client.getProperties().put(SshAgent.SSH_AUTHSOCKET_ENV_NAME, authSock);
        }
        */

        ClientSession session = client.connect(login, host, port).await().getSession();
        session.auth().verify();

        ClientChannel channel;
        if (command == null) {
            channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
            ((ChannelShell) channel).setAgentForwarding(agentForward);
            channel.setIn(new NoCloseInputStream(System.in));
        } else {
            channel = session.createChannel(ClientChannel.CHANNEL_EXEC);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Writer w = new OutputStreamWriter(baos);
            for (String cmd : command) {
                w.append(cmd).append(" ");
            }
            w.append("\n");
            w.close();
            channel.setIn(new ByteArrayInputStream(baos.toByteArray()));
        }
        channel.setOut(new NoCloseOutputStream(System.out));
        channel.setErr(new NoCloseOutputStream(System.err));
        channel.open().await();
        channel.waitFor(ClientChannel.CLOSED, 0);
        session.close(false);
        client.stop();
    }

}
