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
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import org.apache.mina.core.service.IoAcceptor;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.core.session.IoSessionConfig;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.sshd.common.AbstractFactoryManager;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.Cipher;
import org.apache.sshd.common.Compression;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.KeyExchange;
import org.apache.sshd.common.Mac;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Signature;
import org.apache.sshd.common.cipher.AES128CBC;
import org.apache.sshd.common.cipher.AES192CBC;
import org.apache.sshd.common.cipher.AES256CBC;
import org.apache.sshd.common.cipher.BlowfishCBC;
import org.apache.sshd.common.cipher.TripleDESCBC;
import org.apache.sshd.common.compression.CompressionNone;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.mac.HMACMD5;
import org.apache.sshd.common.mac.HMACMD596;
import org.apache.sshd.common.mac.HMACSHA1;
import org.apache.sshd.common.mac.HMACSHA196;
import org.apache.sshd.common.random.BouncyCastleRandom;
import org.apache.sshd.common.random.JceRandom;
import org.apache.sshd.common.random.SingletonRandomFactory;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.signature.SignatureDSA;
import org.apache.sshd.common.signature.SignatureRSA;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;
import org.apache.sshd.server.FileSystemFactory;
import org.apache.sshd.server.ForwardingFilter;
import org.apache.sshd.server.PasswordAuthenticator;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.auth.UserAuthPassword;
import org.apache.sshd.server.auth.UserAuthPublicKey;
import org.apache.sshd.server.auth.gss.GSSAuthenticator;
import org.apache.sshd.server.auth.gss.UserAuthGSS;
import org.apache.sshd.server.channel.ChannelDirectTcpip;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.filesystem.NativeFileSystemFactory;
import org.apache.sshd.server.kex.DHG1;
import org.apache.sshd.server.kex.DHG14;
import org.apache.sshd.server.keyprovider.PEMGeneratorHostKeyProvider;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.session.SessionFactory;
import org.apache.sshd.server.shell.ProcessShellFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
public class SshServer extends AbstractFactoryManager implements ServerFactoryManager {

    private final Logger log = LoggerFactory.getLogger(getClass());

    protected IoAcceptor acceptor;
    protected String host;
    protected int port;
    protected int backlog = 50;
    protected boolean reuseAddress = true;
    protected IoSessionConfig sessionConfig;
    protected List<NamedFactory<UserAuth>> userAuthFactories;
    protected Factory<Command> shellFactory;
    protected SessionFactory sessionFactory;
    protected CommandFactory commandFactory;
    protected FileSystemFactory fileSystemFactory;
    protected List<NamedFactory<Command>> subsystemFactories;
    protected PasswordAuthenticator passwordAuthenticator;
    protected PublickeyAuthenticator publickeyAuthenticator;
    protected GSSAuthenticator gssAuthenticator;
    protected ForwardingFilter forwardingFilter;
    protected ScheduledExecutorService executor;
    protected boolean shutdownExecutor;

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

    public boolean getReuseAddress() {
        return reuseAddress;
    }

    public void setReuseAddress(boolean reuseAddress) {
        this.reuseAddress = reuseAddress;
    }

    public int getBacklog() {
        return backlog;
    }

    public void setBacklog(int backlog) {
        this.backlog = backlog;
    }

    public IoSessionConfig getSessionConfig() {
        return sessionConfig;
    }

    public void setSessionConfig(IoSessionConfig sessionConfig) {
        this.sessionConfig = sessionConfig;
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

    public FileSystemFactory getFileSystemFactory() {
        return fileSystemFactory;
    }

    public void setFileSystemFactory(FileSystemFactory fileSystemFactory) {
        this.fileSystemFactory = fileSystemFactory;
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

    public ForwardingFilter getForwardingFilter() {
        return forwardingFilter;
    }

    public void setForwardingFilter(ForwardingFilter forwardingFilter) {
        this.forwardingFilter = forwardingFilter;
    }

    public ScheduledExecutorService getScheduledExecutorService() {
        return executor;
    }

    public void setScheduledExecutorService(ScheduledExecutorService executor) {
        setScheduledExecutorService(executor, false);
    }

    public void setScheduledExecutorService(ScheduledExecutorService executor, boolean shutdownExecutor) {
        this.executor = executor;
        this.shutdownExecutor = shutdownExecutor;
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
            setScheduledExecutorService(Executors.newSingleThreadScheduledExecutor(), true);
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
    }

    /**
     * Start the SSH server and accept incoming exceptions on the configured port.
     * 
     * @throws IOException
     */
    public void start() throws IOException {
        checkConfig();
        acceptor = createAcceptor();
        configure(acceptor);

        SessionFactory handler = sessionFactory;
        if (handler == null) {
            handler = createSessionFactory();
        }
        handler.setServer(this);
        acceptor.setHandler(handler);

        acceptor.bind(host != null ? new InetSocketAddress(host, port) : new InetSocketAddress(port));
        if (port == 0) {
            port = ((InetSocketAddress) acceptor.getLocalAddress()).getPort();
        }
    }

    /**
     * Stop the SSH server.  This method will block until all resources are actually disposed.
     */
    public void stop() throws InterruptedException {
        stop(false);
    }

    public void stop(boolean immediately) throws InterruptedException {
        acceptor.setCloseOnDeactivation(false);
        acceptor.unbind();
        List<AbstractSession> sessions = new ArrayList<AbstractSession>();
        for (IoSession ioSession : acceptor.getManagedSessions().values()) {
            AbstractSession session = AbstractSession.getSession(ioSession, true);
            if (session != null) {
                sessions.add(session);
            }
        }
        final CountDownLatch latch = new CountDownLatch(sessions.size());
        SshFutureListener<CloseFuture> listener = new SshFutureListener<CloseFuture>() {
            public void operationComplete(CloseFuture future) {
                latch.countDown();
            }
        };
        for (AbstractSession session : sessions) {
            session.close(immediately).addListener(listener);
        }
        if (!immediately) {
            latch.await();
        }
        acceptor.dispose();
        acceptor = null;
        if (shutdownExecutor && executor != null) {
            executor.shutdown();
            executor = null;
        }
    }

    protected IoAcceptor createAcceptor() {
        return new NioSocketAcceptor(getNioWorkers());
    }

    protected void configure(IoAcceptor acceptor) {
        if (acceptor instanceof NioSocketAcceptor) {
            final NioSocketAcceptor nio = (NioSocketAcceptor) acceptor;
            nio.setReuseAddress(reuseAddress);
            nio.setBacklog(backlog);

            // MINA itself forces our socket receive buffer to 1024 bytes
            // by default, despite what the operating system defaults to.
            // This limits us to about 3 MB/s incoming data transfer.  By
            // forcing back to the operating system default we can get a
            // decent transfer rate again.
            //
            final Socket s = new Socket();
            try {
              try {
                  nio.getSessionConfig().setReceiveBufferSize(s.getReceiveBufferSize());
              } finally {
                  s.close();
              }
            } catch (IOException e) {
                log.warn("cannot adjust SO_RCVBUF back to system default", e);
            }
        }
        if (sessionConfig != null) {
            acceptor.getSessionConfig().setAll(sessionConfig);
        }
    }

    protected SessionFactory createSessionFactory() {
        return new SessionFactory();
    }

    public static SshServer setUpDefaultServer() {
        SshServer sshd = new SshServer();
        // DHG14 uses 2048 bits key which are not supported by the default JCE provider
        if (SecurityUtils.isBouncyCastleRegistered()) {
            sshd.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>>asList(
                    new DHG14.Factory(),
                    new DHG1.Factory()));
            sshd.setRandomFactory(new SingletonRandomFactory(new BouncyCastleRandom.Factory()));
        } else {
            sshd.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>>asList(
                    new DHG1.Factory()));
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
                new HMACMD5.Factory(),
                new HMACSHA1.Factory(),
                new HMACMD596.Factory(),
                new HMACSHA196.Factory()));
        sshd.setChannelFactories(Arrays.<NamedFactory<Channel>>asList(
                new ChannelSession.Factory(),
                new ChannelDirectTcpip.Factory()));
        sshd.setSignatureFactories(Arrays.<NamedFactory<Signature>>asList(
                new SignatureDSA.Factory(),
                new SignatureRSA.Factory()));
        sshd.setFileSystemFactory(new NativeFileSystemFactory());
        return sshd;
    }

    private static void setUpDefaultCiphers(SshServer sshd) {
        List<NamedFactory<Cipher>> avail = new LinkedList<NamedFactory<Cipher>>();
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
        boolean error = false;

        for (int i = 0; i < args.length; i++) {
            if ("-p".equals(args[i])) {
                if (i + 1 >= args.length) {
                    System.err.println("option requires an argument: " + args[i]);
                    break;
                }
                port = Integer.parseInt(args[++i]);
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
            System.err.println("usage: sshd [-p port]");
            System.exit(-1);
        }

        System.err.println("Starting SSHD on port " + port);
                                                    
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
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
        sshd.setForwardingFilter(new ForwardingFilter() {
            public boolean canForwardAgent(ServerSession session) {
                return true;
            }

            public boolean canForwardX11(ServerSession session) {
                return true;
            }

            public boolean canListen(InetSocketAddress address, ServerSession session) {
                return true;
            }

            public boolean canConnect(InetSocketAddress address, ServerSession session) {
                return true;
            }
        });
        sshd.start();
    }

}
