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

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.AbstractFactoryManager;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.Cipher;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.Compression;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.ForwardingFilter;
import org.apache.sshd.common.RequestHandler;
import org.apache.sshd.common.KeyExchange;
import org.apache.sshd.common.Mac;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.Signature;
import org.apache.sshd.common.SshdSocketAddress;
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
import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.DefaultIoServiceFactoryFactory;
import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.mina.MinaServiceFactory;
import org.apache.sshd.common.io.nio2.Nio2ServiceFactory;
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
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.signature.SignatureDSA;
import org.apache.sshd.common.signature.SignatureECDSA;
import org.apache.sshd.common.signature.SignatureRSA;
import org.apache.sshd.common.util.CloseableUtils;
import org.apache.sshd.common.util.IoUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.ThreadUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;
import org.apache.sshd.server.PasswordAuthenticator;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.auth.UserAuthKeyboardInteractive;
import org.apache.sshd.server.auth.UserAuthPassword;
import org.apache.sshd.server.auth.UserAuthPublicKey;
import org.apache.sshd.server.auth.gss.GSSAuthenticator;
import org.apache.sshd.server.auth.gss.UserAuthGSS;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.server.global.CancelTcpipForwardHandler;
import org.apache.sshd.server.global.KeepAliveHandler;
import org.apache.sshd.server.global.NoMoreSessionsHandler;
import org.apache.sshd.server.global.TcpipForwardHandler;
import org.apache.sshd.server.kex.DHG1;
import org.apache.sshd.server.kex.DHG14;
import org.apache.sshd.server.kex.DHGEX;
import org.apache.sshd.server.kex.DHGEX256;
import org.apache.sshd.server.kex.ECDHP256;
import org.apache.sshd.server.kex.ECDHP384;
import org.apache.sshd.server.kex.ECDHP521;
import org.apache.sshd.server.keyprovider.PEMGeneratorHostKeyProvider;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerConnectionService;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.session.ServerUserAuthService;
import org.apache.sshd.server.session.SessionFactory;
import org.apache.sshd.server.sftp.SftpSubsystem;
import org.apache.sshd.server.session.ServerSessionTimeoutListener;
import org.apache.sshd.server.shell.ProcessShellFactory;

/**
 * The SshServer class is the main entry point for the server side of the SSH protocol.
 *
 * The SshServer has to be configured before being started.  Such configuration can be
 * done either using a dependency injection mechanism (such as the Spring framework)
 * or programmatically. Basic setup is usually done using the {@link #setUpDefaultServer()}
 * method, which will known ciphers, macs, channels, etc...
 * Besides this basic setup, a few things have to be manually configured such as the
 * port number, {@link Factory}, the {@link org.apache.sshd.common.KeyPairProvider}
 * and the {@link PasswordAuthenticator}.
 *
 * Some properties can also be configured using the {@link #setProperties(java.util.Map)}
 * method.
 *
 * Once the SshServer instance has been configured, it can be started using the
 * {@link #start()} method and stopped using the {@link #stop()} method.
 *
 * @see ServerFactoryManager
 * @see org.apache.sshd.common.FactoryManager
 *
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshServer extends AbstractFactoryManager implements ServerFactoryManager, Closeable {

    protected IoAcceptor acceptor;
    protected String host;
    protected int port;
    protected List<NamedFactory<UserAuth>> userAuthFactories;
    protected Factory<Command> shellFactory;
    protected SessionFactory sessionFactory;
    protected CommandFactory commandFactory;
    protected List<NamedFactory<Command>> subsystemFactories;
    protected PasswordAuthenticator passwordAuthenticator;
    protected PublickeyAuthenticator publickeyAuthenticator;
    protected GSSAuthenticator gssAuthenticator;
    protected ServerSessionTimeoutListener sessionTimeoutListener;
    protected ScheduledFuture<?> timeoutListenerFuture;

    public SshServer() {
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    /**
     * Configure the port number to use for this SSH server.
     *
     * @param port the port number for this SSH server
     */
    public void setPort(int port) {
        this.port = port;
    }

    public List<NamedFactory<UserAuth>> getUserAuthFactories() {
        return userAuthFactories;
    }

    public void setUserAuthFactories(List<NamedFactory<UserAuth>> userAuthFactories) {
        this.userAuthFactories = userAuthFactories;
    }

    public Factory<Command> getShellFactory() {
        return shellFactory;
    }

    public void setShellFactory(Factory<Command> shellFactory) {
        this.shellFactory = shellFactory;
    }

    public SessionFactory getSessionFactory() {
        return sessionFactory;
    }

    public void setSessionFactory(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    public CommandFactory getCommandFactory() {
        return commandFactory;
    }

    public void setCommandFactory(CommandFactory commandFactory) {
        this.commandFactory = commandFactory;
    }

    public List<NamedFactory<Command>> getSubsystemFactories() {
        return subsystemFactories;
    }

    public void setSubsystemFactories(List<NamedFactory<Command>> subsystemFactories) {
        this.subsystemFactories = subsystemFactories;
    }

    public PasswordAuthenticator getPasswordAuthenticator() {
        return passwordAuthenticator;
    }

    public void setPasswordAuthenticator(PasswordAuthenticator passwordAuthenticator) {
        this.passwordAuthenticator = passwordAuthenticator;
    }

    public PublickeyAuthenticator getPublickeyAuthenticator() {
        return publickeyAuthenticator;
    }

    public void setPublickeyAuthenticator(PublickeyAuthenticator publickeyAuthenticator) {
        this.publickeyAuthenticator = publickeyAuthenticator;
    }

    public GSSAuthenticator getGSSAuthenticator() {
      return gssAuthenticator;
    }

    public void setGSSAuthenticator(GSSAuthenticator gssAuthenticator) {
      this.gssAuthenticator = gssAuthenticator;
    }

    public void setTcpipForwardingFilter(ForwardingFilter forwardingFilter) {
        this.tcpipForwardingFilter = forwardingFilter;
    }

    protected void checkConfig() {
        if (getPort() < 0) {
            throw new IllegalArgumentException("Bad port number: " + port);
        }
        if (getKeyExchangeFactories() == null) {
            throw new IllegalArgumentException("KeyExchangeFactories not set");
        }
        if (getUserAuthFactories() == null) {
            List<NamedFactory<UserAuth>> factories = new ArrayList<NamedFactory<UserAuth>>();
            if (getPasswordAuthenticator() != null) {
                factories.add(new UserAuthPassword.Factory());
                factories.add(new UserAuthKeyboardInteractive.Factory());
            }
            if (getPublickeyAuthenticator() != null) {
                factories.add(new UserAuthPublicKey.Factory());
            }
            if (getGSSAuthenticator() != null) {
              factories.add(new UserAuthGSS.Factory());
            }
            if (factories.size() > 0) {
                setUserAuthFactories(factories);
            } else {
                throw new IllegalArgumentException("UserAuthFactories not set");
            }
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
        if (getChannelFactories() == null) {
            throw new IllegalArgumentException("ChannelFactories not set");
        }
        if (getRandomFactory() == null) {
            throw new IllegalArgumentException("RandomFactory not set");
        }
        if (getKeyPairProvider() == null) {
            throw new IllegalArgumentException("HostKeyProvider not set");
        }
        if (getFileSystemFactory() == null) {
            throw new IllegalArgumentException("FileSystemFactory not set");
        }
        if (getIoServiceFactoryFactory() == null) {
            setIoServiceFactoryFactory(new DefaultIoServiceFactoryFactory());
        }
        if (getServiceFactories() == null) {
            setServiceFactories(Arrays.asList(
                    new ServerUserAuthService.Factory(),
                    new ServerConnectionService.Factory()
            ));
        }
    }

    /**
     * Start the SSH server and accept incoming exceptions on the configured port.
     * 
     * @throws IOException
     */
    public void start() throws IOException {
        checkConfig();
        if (sessionFactory == null) {
            sessionFactory = createSessionFactory();
        }
        sessionFactory.setServer(this);
        acceptor = createAcceptor();

        // set up the the session timeout listener and schedule it
        sessionTimeoutListener = createSessionTimeoutListener();
        sessionFactory.addListener(sessionTimeoutListener);

        timeoutListenerFuture = getScheduledExecutorService()
                .scheduleAtFixedRate(sessionTimeoutListener, 1, 1, TimeUnit.SECONDS);

        if (host != null) {
            String[] hosts = host.split(",");
            for (String host : hosts) {
                InetAddress[] inetAddresses = InetAddress.getAllByName(host);
                for (InetAddress inetAddress : inetAddresses) {
                    acceptor.bind(new InetSocketAddress(inetAddress, port));
                    if (port == 0) {
                        port = ((InetSocketAddress) acceptor.getBoundAddresses().iterator().next()).getPort();
                    }
                }
            }
        } else {
            acceptor.bind(new InetSocketAddress(port));
            if (port == 0) {
                port = ((InetSocketAddress) acceptor.getBoundAddresses().iterator().next()).getPort();
            }
        }
    }

    /**
     * Stop the SSH server.  This method will block until all resources are actually disposed.
     */
    public void stop() throws InterruptedException {
        stop(false);
    }

    public void stop(boolean immediately) throws InterruptedException {
        close(immediately).await();
    }

    public void open() throws IOException {
        start();
    }

    @Override
    protected CloseFuture doCloseGracefully() {
        stopSessionTimeoutListener();
        CloseFuture future;
        if (acceptor != null) {
            future = CloseableUtils.sequential(acceptor, ioServiceFactory).close(false);
        } else if (ioServiceFactory != null) {
            future = ioServiceFactory.close(false);
        } else {
            future = CloseableUtils.closed();
        }
        return future;
    }

    @Override
    protected void doCloseImmediately() {
        CloseableUtils.sequential(acceptor, ioServiceFactory).close(true);
        acceptor = null;
        ioServiceFactory = null;
        if (shutdownExecutor && executor != null) {
            executor.shutdown();
            executor = null;
        }
        super.doCloseImmediately();
    }

    /**
     * Obtain the list of active sessions.
     */
    public List<AbstractSession> getActiveSessions() {
        List<AbstractSession> sessions = new ArrayList<AbstractSession>();
        for (IoSession ioSession : acceptor.getManagedSessions().values()) {
            AbstractSession session = AbstractSession.getSession(ioSession, true);
            if (session != null) {
                sessions.add(session);
            }
        }
        return sessions;
    }

    protected IoAcceptor createAcceptor() {
        return getIoServiceFactory().createAcceptor(getSessionFactory());
    }

    protected SessionFactory createSessionFactory() {
        return new SessionFactory();
    }

    protected ServerSessionTimeoutListener createSessionTimeoutListener() {
        return new ServerSessionTimeoutListener();
    }

    protected void stopSessionTimeoutListener() {
        // cancel the timeout monitoring task
        if (timeoutListenerFuture != null) {
            timeoutListenerFuture.cancel(true);
            timeoutListenerFuture = null;
        }

        // remove the sessionTimeoutListener completely; should the SSH server be restarted, a new one
        // will be created.
        if (sessionFactory != null && sessionTimeoutListener != null) {
            sessionFactory.removeListener(sessionTimeoutListener);
        }
        sessionTimeoutListener = null;
    }

    @Override
    public String toString() {
        return "SshServer[" + Integer.toHexString(hashCode()) + "]";
    }

    public static SshServer setUpDefaultServer() {
        SshServer sshd = new SshServer();
        // DHG14 uses 2048 bits key which are not supported by the default JCE provider
        // EC keys are not supported until OpenJDK 8
        if (SecurityUtils.isBouncyCastleRegistered()) {
            sshd.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>>asList(
                    new DHGEX256.Factory(),
                    new DHGEX.Factory(),
                    new ECDHP256.Factory(),
                    new ECDHP384.Factory(),
                    new ECDHP521.Factory(),
                    new DHG14.Factory(),
                    new DHG1.Factory()));
            sshd.setSignatureFactories(Arrays.<NamedFactory<Signature>>asList(
                    new SignatureECDSA.NISTP256Factory(),
                    new SignatureECDSA.NISTP384Factory(),
                    new SignatureECDSA.NISTP521Factory(),
                    new SignatureDSA.Factory(),
                    new SignatureRSA.Factory()));
            sshd.setRandomFactory(new SingletonRandomFactory(new BouncyCastleRandom.Factory()));
        // EC keys are not supported until OpenJDK 7
        } else if (SecurityUtils.hasEcc()) {
            sshd.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>>asList(
                    new DHGEX256.Factory(),
                    new DHGEX.Factory(),
                    new ECDHP256.Factory(),
                    new ECDHP384.Factory(),
                    new ECDHP521.Factory(),
                    new DHG1.Factory()));
            sshd.setSignatureFactories(Arrays.<NamedFactory<Signature>>asList(
                    new SignatureECDSA.NISTP256Factory(),
                    new SignatureECDSA.NISTP384Factory(),
                    new SignatureECDSA.NISTP521Factory(),
                    new SignatureDSA.Factory(),
                    new SignatureRSA.Factory()));
            sshd.setRandomFactory(new SingletonRandomFactory(new JceRandom.Factory()));
        } else {
            sshd.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>>asList(
                    new DHGEX256.Factory(),
                    new DHGEX.Factory(),
                    new DHG1.Factory()));
            sshd.setSignatureFactories(Arrays.<NamedFactory<Signature>>asList(
                    new SignatureDSA.Factory(),
                    new SignatureRSA.Factory()));
            sshd.setRandomFactory(new SingletonRandomFactory(new JceRandom.Factory()));
        }
        setUpDefaultCiphers(sshd);
        // Compression is not enabled by default
        // sshd.setCompressionFactories(Arrays.<NamedFactory<Compression>>asList(
        //         new CompressionNone.Factory(),
        //         new CompressionZlib.Factory(),
        //         new CompressionDelayedZlib.Factory()));
        sshd.setCompressionFactories(Arrays.<NamedFactory<Compression>>asList(
                new CompressionNone.Factory()));
        sshd.setMacFactories(Arrays.<NamedFactory<Mac>>asList(
                new HMACSHA256.Factory(),
                new HMACSHA512.Factory(),
                new HMACSHA1.Factory(),
                new HMACMD5.Factory(),
                new HMACSHA196.Factory(),
                new HMACMD596.Factory()));
        sshd.setChannelFactories(Arrays.<NamedFactory<Channel>>asList(
                new ChannelSession.Factory(),
                new TcpipServerChannel.DirectTcpipFactory()));
        sshd.setFileSystemFactory(new NativeFileSystemFactory());
        sshd.setTcpipForwarderFactory(new DefaultTcpipForwarderFactory());
        sshd.setGlobalRequestHandlers(Arrays.<RequestHandler<ConnectionService>>asList(
                new KeepAliveHandler(),
                new NoMoreSessionsHandler(),
                new TcpipForwardHandler(),
                new CancelTcpipForwardHandler()
        ));
        return sshd;
    }

    private static void setUpDefaultCiphers(SshServer sshd) {
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
        sshd.setCipherFactories(avail);
    }

    /*=================================
          Main class implementation
     *=================================*/

    public static void main(String[] args) throws Exception {
        int port = 8000;
        String provider;
        boolean error = false;

        for (int i = 0; i < args.length; i++) {
            if ("-p".equals(args[i])) {
                if (i + 1 >= args.length) {
                    System.err.println("option requires an argument: " + args[i]);
                    break;
                }
                port = Integer.parseInt(args[++i]);
            } else if ("-io".equals(args[i])) {
                if (i + 1 >= args.length) {
                    System.err.println("option requires an argument: " + args[i]);
                    break;
                }
                provider = args[++i];
                if ("mina".equals(provider)) {
                    System.setProperty(IoServiceFactory.class.getName(), MinaServiceFactory.class.getName());
                } else if ("nio2".endsWith(provider)) {
                    System.setProperty(IoServiceFactory.class.getName(), Nio2ServiceFactory.class.getName());
                } else {
                    System.err.println("provider should be mina or nio2: " + args[i]);
                    break;
                }
            } else if (args[i].startsWith("-")) {
                System.err.println("illegal option: " + args[i]);
                error = true;
                break;
            } else {
                System.err.println("extra argument: " + args[i]);
                error = true;
                break;
            }
        }
        if (error) {
            System.err.println("usage: sshd [-p port] [-io mina|nio2]");
            System.exit(-1);
        }

        System.err.println("Starting SSHD on port " + port);
                                                    
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.getProperties().put(SshServer.WELCOME_BANNER, "Welcome to SSHD\n");
        if (SecurityUtils.isBouncyCastleRegistered()) {
            sshd.setKeyPairProvider(new PEMGeneratorHostKeyProvider("key.pem"));
        } else {
            sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider("key.ser"));
        }
        if (OsUtils.isUNIX()) {
            sshd.setShellFactory(new ProcessShellFactory(new String[] { "/bin/sh", "-i", "-l" },
                                 EnumSet.of(ProcessShellFactory.TtyOptions.ONlCr)));
        } else {
            sshd.setShellFactory(new ProcessShellFactory(new String[] { "cmd.exe "},
                                 EnumSet.of(ProcessShellFactory.TtyOptions.Echo, ProcessShellFactory.TtyOptions.ICrNl, ProcessShellFactory.TtyOptions.ONlCr)));
        }
        sshd.setPasswordAuthenticator(new PasswordAuthenticator() {
            public boolean authenticate(String username, String password, ServerSession session) {
                return username != null && username.equals(password);
            }
        });
        sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
            public boolean authenticate(String username, PublicKey key, ServerSession session) {
                //File f = new File("/Users/" + username + "/.ssh/authorized_keys");
                return true;
            }
        });
        sshd.setTcpipForwardingFilter(new ForwardingFilter() {
            public boolean canForwardAgent(Session session) {
                return true;
            }

            public boolean canForwardX11(Session session) {
                return true;
            }

            public boolean canListen(SshdSocketAddress address, Session session) {
                return true;
            }

            public boolean canConnect(SshdSocketAddress address, Session session) {
                return true;
            }
        });
        sshd.setCommandFactory(new ScpCommandFactory(new CommandFactory() {
            public Command createCommand(String command) {
                EnumSet<ProcessShellFactory.TtyOptions> ttyOptions;
                if (OsUtils.isUNIX()) {
                    ttyOptions = EnumSet.of(ProcessShellFactory.TtyOptions.ONlCr);
                } else {
                    ttyOptions = EnumSet.of(ProcessShellFactory.TtyOptions.Echo, ProcessShellFactory.TtyOptions.ICrNl, ProcessShellFactory.TtyOptions.ONlCr);
                }
                return new ProcessShellFactory(command.split(" "), ttyOptions).create();
            }
        }));
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(
                new SftpSubsystem.Factory()
        ));
        sshd.start();

        Thread.sleep(Long.MAX_VALUE);
    }

}
