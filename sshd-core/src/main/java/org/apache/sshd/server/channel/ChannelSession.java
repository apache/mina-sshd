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
package org.apache.sshd.server.channel;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.PtyMode;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.channel.ChannelPipedInputStream;
import org.apache.sshd.common.channel.ChannelPipedOutputStream;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.IoUtils;
import org.apache.sshd.common.util.LoggingFilterOutputStream;
import org.apache.sshd.server.*;
import org.apache.sshd.server.FileSystemFactory;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.x11.X11ForwardSupport;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelSession extends AbstractServerChannel {

    public static class Factory implements NamedFactory<Channel> {

        public String getName() {
            return "session";
        }

        public Channel create() {
            return new ChannelSession();
        }
    }

    protected static class StandardEnvironment implements Environment {

        private final Map<Signal, Set<SignalListener>> listeners;
        private final Map<String, String> env;
        private final Map<PtyMode, Integer> ptyModes;

        public StandardEnvironment() {
            listeners = new ConcurrentHashMap<Signal, Set<SignalListener>>(3);
            env = new ConcurrentHashMap<String, String>();
            ptyModes = new ConcurrentHashMap<PtyMode, Integer>();
        }

        public void addSignalListener(SignalListener listener, Signal... signals) {
            if (signals == null) {
                throw new IllegalArgumentException("signals may not be null");
            }
            if (listener == null) {
                throw new IllegalArgumentException("listener may not be null");
            }
            for (Signal s : signals) {
                getSignalListeners(s, true).add(listener);
            }
        }

        public void addSignalListener(SignalListener listener) {
            addSignalListener(listener, EnumSet.allOf(Signal.class));
        }

        public void addSignalListener(SignalListener listener, EnumSet<Signal> signals) {
            if (signals == null) {
                throw new IllegalArgumentException("signals may not be null");
            }
            addSignalListener(listener, signals.toArray(new Signal[signals.size()]));
        }

        public Map<String, String> getEnv() {
            return env;
        }

        public Map<PtyMode, Integer> getPtyModes() {
            return ptyModes;
        }

        public void removeSignalListener(SignalListener listener) {
            if (listener == null) {
                throw new IllegalArgumentException("listener may not be null");
            }
            for (Signal s : EnumSet.allOf(Signal.class)) {
                final Set<SignalListener> ls = getSignalListeners(s, false);
                if (ls != null) {
                    ls.remove(listener);
                }
            }
        }

        public void signal(Signal signal) {
            final Set<SignalListener> ls = getSignalListeners(signal, false);
            if (ls != null) {
                for (SignalListener l : ls) {
                    l.signal(signal);
                }
            }
        }

        /**
         * adds a variable to the environment. This method is called <code>set</code>
         * according to the name of the appropriate posix command <code>set</code>
         * @param key environment variable name
         * @param value environment variable value
         */
        public void set(String key, String value) {
            // TODO: listening for property changes would be nice too.
            getEnv().put(key, value);
        }

        protected Set<SignalListener> getSignalListeners(Signal signal, boolean create) {
            Set<SignalListener> ls = listeners.get(signal);
            if (ls == null && create) {
                synchronized (listeners) {
                    ls = listeners.get(signal);
                    if (ls == null) {
                        ls = new CopyOnWriteArraySet<SignalListener>();
                        listeners.put(signal, ls);
                    }
                }
            }
            // may be null in case create=false
            return ls;
        }

    }

    protected String type;
    protected InputStream in;
    protected OutputStream out;
    protected OutputStream err;
    protected Command command;
    protected OutputStream shellIn;
    protected StandardEnvironment env = new StandardEnvironment();

    public ChannelSession() {
    }

    public CloseFuture close(boolean immediately) {
        return super.close(immediately).addListener(new SshFutureListener() {
            public void operationComplete(SshFuture sshFuture) {
                if (command != null) {
                    command.destroy();
                    command = null;
                }
                remoteWindow.notifyClosed();
                IoUtils.closeQuietly(in, out, err, shellIn);
            }
        });
    }

    @Override
    public void handleEof() throws IOException {
        super.handleEof();
        shellIn.close();
    }

    public void handleRequest(Buffer buffer) throws IOException {
        log.debug("Received SSH_MSG_CHANNEL_REQUEST on channel {}", id);
        String type = buffer.getString();
        log.debug("Received channel request: {}", type);
        if (!handleRequest(type, buffer)) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_FAILURE, 0);
            buffer.putInt(recipient);
            session.writePacket(buffer);
        }
    }

    protected void doWriteData(byte[] data, int off, int len) throws IOException {
        if (shellIn != null) {
            shellIn.write(data, off, len);
            shellIn.flush();
        }
    }

    protected void doWriteExtendedData(byte[] data, int off, int len) throws IOException {
        throw new UnsupportedOperationException("Server channel does not support extended data");
    }

    protected boolean handleRequest(String type, Buffer buffer) throws IOException {
        if ("env".equals(type)) {
            return handleEnv(buffer);
        }
        if ("pty-req".equals(type)) {
            return handlePtyReq(buffer);
        }
        if ("window-change".equals(type)) {
            return handleWindowChange(buffer);
        }
        if ("signal".equals(type)) {
            return handleSignal(buffer);
        }
        if ("shell".equals(type)) {
            if (this.type == null && handleShell(buffer)) {
                this.type = type;
                return true;
            } else {
                return false;
            }
        }
        if ("exec".equals(type)) {
            if (this.type == null && handleExec(buffer)) {
                this.type = type;
                return true;
            } else {
                return false;
            }
        }
        if ("subsystem".equals(type)) {
            if (this.type == null && handleSubsystem(buffer)) {
                this.type = type;
                return true;
            } else {
                return false;
            }
        }
        if ("auth-agent-req@openssh.com".equals(type)) {
            return handleAgentForwarding(buffer);
        }
        if ("x11-req".equals(type)) {
            return handleX11Forwarding(buffer);
        }
        if (type != null && type.endsWith("@putty.projects.tartarus.org")) {
            // Ignore but accept, more doc at
            // http://tartarus.org/~simon/putty-snapshots/htmldoc/AppendixF.html
            return true;
        }
        return false;
    }

    protected boolean handleEnv(Buffer buffer) throws IOException {
        boolean wantReply = buffer.getBoolean();
        String name = buffer.getString();
        String value = buffer.getString();
        addEnvVariable(name, value);
        log.debug("env for channel {}: {} = {}", new Object[] { id, name, value });
        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_SUCCESS, 0);
            buffer.putInt(recipient);
            session.writePacket(buffer);
        }
        return true;
    }

    protected boolean handlePtyReq(Buffer buffer) throws IOException {
        boolean wantReply = buffer.getBoolean();
        String term = buffer.getString();
        int tColumns = buffer.getInt();
        int tRows = buffer.getInt();
        int tWidth = buffer.getInt();
        int tHeight = buffer.getInt();
        byte[] modes = buffer.getBytes();
        for (int i = 0; i < modes.length && modes[i] != 0;) {
            PtyMode mode = PtyMode.fromInt(modes[i++]);
            int val  = ((modes[i++] << 24) & 0xff000000) |
                       ((modes[i++] << 16) & 0x00ff0000) |
                       ((modes[i++] <<  8) & 0x0000ff00) |
                       ((modes[i++]      ) & 0x000000ff);
            getEnvironment().getPtyModes().put(mode, val);
        }
        if (log.isDebugEnabled()) {
            log.debug("pty for channel {}: term={}, size=({} - {}), pixels=({}, {}), modes=[{}]", new Object[] { id, term, tColumns, tRows, tWidth, tHeight, getEnvironment().getPtyModes() });
        }
        addEnvVariable(Environment.ENV_TERM, term);
        addEnvVariable(Environment.ENV_COLUMNS, Integer.toString(tColumns));
        addEnvVariable(Environment.ENV_LINES, Integer.toString(tRows));
        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_SUCCESS, 0);
            buffer.putInt(recipient);
            session.writePacket(buffer);
        }
        return true;
    }

    protected boolean handleWindowChange(Buffer buffer) throws IOException {
        boolean wantReply = buffer.getBoolean();
        int tColumns = buffer.getInt();
        int tRows = buffer.getInt();
        int tWidth = buffer.getInt();
        int tHeight = buffer.getInt();
        log.debug("window-change for channel {}: ({} - {}), ({}, {})", new Object[] { id, tColumns, tRows, tWidth, tHeight });

        final StandardEnvironment e = getEnvironment();
        e.set(Environment.ENV_COLUMNS, Integer.toString(tColumns));
        e.set(Environment.ENV_LINES, Integer.toString(tRows));
        e.signal(Signal.WINCH);

        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_SUCCESS, 0);
            buffer.putInt(recipient);
            session.writePacket(buffer);
        }
        return true;
    }

    protected boolean handleSignal(Buffer buffer) throws IOException {
        boolean wantReply = buffer.getBoolean();
        String name = buffer.getString();
        log.debug("Signal received on channel {}: {}", id, name);

        final Signal signal = Signal.get(name);
        if (signal != null) {
            getEnvironment().signal(signal);
        } else {
            log.warn("Unknown signal received: " + name);
        }


        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_SUCCESS, 0);
            buffer.putInt(recipient);
            session.writePacket(buffer);
        }
        return true;
    }

    protected boolean handleShell(Buffer buffer) throws IOException {
        boolean wantReply = buffer.getBoolean();
        if (((ServerSession) session).getServerFactoryManager().getShellFactory() == null) {
            return false;
        }
        command = ((ServerSession) session).getServerFactoryManager().getShellFactory().create();
        prepareCommand();
        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_SUCCESS, 0);
            buffer.putInt(recipient);
            session.writePacket(buffer);
        }
        command.start(getEnvironment());
        return true;
    }

    protected boolean handleExec(Buffer buffer) throws IOException {
        boolean wantReply = buffer.getBoolean();
        String commandLine = buffer.getString();
        if (((ServerSession) session).getServerFactoryManager().getCommandFactory() == null) {
            return false;
        }
        if (log.isInfoEnabled()) {
            log.info("Executing command: {}", commandLine);
        }
        try {
            command = ((ServerSession) session).getServerFactoryManager().getCommandFactory().createCommand(commandLine);
        } catch (IllegalArgumentException iae) {
            // TODO: Shouldn't we log errors on the server side?
            return false;
        }
        prepareCommand();
        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_SUCCESS, 0);
            buffer.putInt(recipient);
            session.writePacket(buffer);
        }
        // Launch command
        command.start(getEnvironment());
        return true;
    }

    protected boolean handleSubsystem(Buffer buffer) throws IOException {
        boolean wantReply = buffer.getBoolean();
        String subsystem = buffer.getString();
        List<NamedFactory<Command>> factories = ((ServerSession) session).getServerFactoryManager().getSubsystemFactories();
        if (factories == null) {
            return false;
        }
        command = NamedFactory.Utils.create(factories, subsystem);
        if (command == null) {
            return false;
        }
        prepareCommand();
        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_SUCCESS, 0);
            buffer.putInt(recipient);
            session.writePacket(buffer);
        }
        // Launch command
        command.start(getEnvironment());
        return true;
    }

    protected void prepareCommand() throws IOException {
        // Add the user
        addEnvVariable(Environment.ENV_USER, ((ServerSession) session).getUsername());
        // If the shell wants to be aware of the session, let's do that
        if (command instanceof SessionAware) {
            ((SessionAware) command).setSession((ServerSession) session);
        }
        // If the shell wants to be aware of the file system, let's do that too
        if (command instanceof FileSystemAware) {
            FileSystemFactory factory = ((ServerSession) session).getServerFactoryManager().getFileSystemFactory();
            ((FileSystemAware) command).setFileSystemView(factory.createFileSystemView(session));
        }
        out = new ChannelOutputStream(this, remoteWindow, log, SshConstants.Message.SSH_MSG_CHANNEL_DATA);
        err = new ChannelOutputStream(this, remoteWindow, log, SshConstants.Message.SSH_MSG_CHANNEL_EXTENDED_DATA);
        in = new ChannelPipedInputStream(localWindow);
        shellIn = new ChannelPipedOutputStream((ChannelPipedInputStream) in);
        if (log != null && log.isTraceEnabled()) {
            // Wrap in logging filters
            out = new LoggingFilterOutputStream(out, "OUT:", log);
            err = new LoggingFilterOutputStream(err, "ERR:", log);
            shellIn = new LoggingFilterOutputStream(shellIn, "IN: ", log);
        }
        command.setInputStream(in);
        command.setOutputStream(out);
        command.setErrorStream(err);
        command.setExitCallback(new ExitCallback() {
            public void onExit(int exitValue) {
                try {
                    closeShell(exitValue);
                } catch (IOException e) {
                    log.info("Error closing shell", e);
                }
            }
            public void onExit(int exitValue, String exitMessage) {
                onExit(exitValue);
            }
        });
    }

    protected int getPtyModeValue(PtyMode mode) {
        Integer v = getEnvironment().getPtyModes().get(mode);
        return v != null ? v : 0;
    }

    protected boolean handleAgentForwarding(Buffer buffer) throws IOException {
        boolean wantReply = buffer.getBoolean();

        final ServerSession server = (ServerSession) session;
        final ForwardingFilter filter = server.getServerFactoryManager().getForwardingFilter();
        final SshAgentFactory factory = server.getServerFactoryManager().getAgentFactory();
        if (factory == null || (filter != null && !filter.canForwardAgent(server))) {
            if (wantReply) {
                buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_FAILURE, 0);
                buffer.putInt(recipient);
                session.writePacket(buffer);
            }
            return true;
        }

        String authSocket = ((ServerSession) session).initAgentForward();
        addEnvVariable(SshAgent.SSH_AUTHSOCKET_ENV_NAME, authSocket);

        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_SUCCESS, 0);
            buffer.putInt(recipient);
            session.writePacket(buffer);
        }
        return true;
    }

    protected boolean handleX11Forwarding(Buffer buffer) throws IOException {
        boolean wantReply = buffer.getBoolean();

        final ServerSession server = (ServerSession) session;
        final ForwardingFilter filter = server.getServerFactoryManager().getForwardingFilter();
        if (filter == null || !filter.canForwardX11(server)) {
            if (wantReply) {
                buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_FAILURE, 0);
                buffer.putInt(recipient);
                session.writePacket(buffer);
            }
            return true;
        }

        String display = ((ServerSession) session).createX11Display(buffer.getBoolean(), buffer.getString(),
                                                                    buffer.getString(), buffer.getInt());
        if (display == null) {
            if (wantReply) {
                buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_FAILURE, 0);
                buffer.putInt(recipient);
                session.writePacket(buffer);
            }
            return true;
        }

        addEnvVariable(X11ForwardSupport.ENV_DISPLAY, display);

        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_SUCCESS, 0);
            buffer.putInt(recipient);
            session.writePacket(buffer);
        }
        return true;
    }

    protected void addEnvVariable(String name, String value) {
        getEnvironment().set(name, value);
    }

    protected StandardEnvironment getEnvironment() {
        return env;
    }

    protected void closeShell(int exitValue) throws IOException {
        if (!closing) {
            sendEof();
            sendExitStatus(exitValue);
            // TODO: We should wait for all streams to be consumed before closing the channel
            close(false);
        }
    }

}
