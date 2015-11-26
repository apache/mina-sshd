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
package org.apache.sshd.server.channel;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.Map;
import java.util.TimerTask;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.AbstractChannelRequestHandler;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelAsyncOutputStream;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.channel.PtyMode;
import org.apache.sshd.common.file.FileSystemAware;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.closeable.IoBaseCloseable;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.LoggingFilterOutputStream;
import org.apache.sshd.server.AsyncCommand;
import org.apache.sshd.server.ChannelSessionAware;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.SessionAware;
import org.apache.sshd.server.Signal;
import org.apache.sshd.server.StandardEnvironment;
import org.apache.sshd.server.forward.ForwardingFilter;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.x11.X11ForwardSupport;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelSession extends AbstractServerChannel {

    protected String type;
    protected ChannelAsyncOutputStream asyncOut;
    protected ChannelAsyncOutputStream asyncErr;
    protected OutputStream out;
    protected OutputStream err;
    protected Command command;
    protected ChannelDataReceiver receiver;
    protected Buffer tempBuffer;
    protected final StandardEnvironment env = new StandardEnvironment();
    protected final CloseFuture commandExitFuture = new DefaultCloseFuture(lock);

    public ChannelSession() {
        addRequestHandler(new ChannelSessionRequestHandler());
        addRequestHandler(new PuttyRequestHandler());
    }

    @Override
    public void handleWindowAdjust(Buffer buffer) throws IOException {
        super.handleWindowAdjust(buffer);
        if (asyncOut != null) {
            asyncOut.onWindowExpanded();
        }
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder()
                .sequential(new CommandCloseable(), new GracefulChannelCloseable())
                .parallel(asyncOut, asyncErr)
                .build();
    }

    public class CommandCloseable extends IoBaseCloseable {
        @Override
        public boolean isClosed() {
            return commandExitFuture.isClosed();
        }

        @Override
        public boolean isClosing() {
            return isClosed();
        }

        @Override
        public CloseFuture close(boolean immediately) {
            if (immediately || command == null) {
                commandExitFuture.setClosed();
            } else if (!commandExitFuture.isClosed()) {
                IOException e = IoUtils.closeQuietly(receiver);
                if (e != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("close({})[immediately={}] failed ({}) to close receiver: {}",
                                  this, immediately, e.getClass().getSimpleName(), e.getMessage());
                    }
                }

                final TimerTask task = new TimerTask() {
                    @Override
                    public void run() {
                        commandExitFuture.setClosed();
                    }
                };

                ChannelSession channel = ChannelSession.this;
                long timeout = PropertyResolverUtils.getLongProperty(
                        channel, ServerFactoryManager.COMMAND_EXIT_TIMEOUT, ServerFactoryManager.DEFAULT_COMMAND_EXIT_TIMEOUT);
                if (log.isDebugEnabled()) {
                    log.debug("Wait {} ms for shell to exit cleanly on {}", Long.valueOf(timeout), channel);
                }

                Session s = channel.getSession();
                FactoryManager manager = ValidateUtils.checkNotNull(s.getFactoryManager(), "No factory manager");
                ScheduledExecutorService scheduler = ValidateUtils.checkNotNull(manager.getScheduledExecutorService(), "No scheduling service");
                scheduler.schedule(task, timeout, TimeUnit.MILLISECONDS);
                commandExitFuture.addListener(new SshFutureListener<CloseFuture>() {
                    @Override
                    public void operationComplete(CloseFuture future) {
                        task.cancel();
                    }
                });
            }
            return commandExitFuture;
        }
    }

    @Override
    protected void doCloseImmediately() {
        if (command != null) {
            try {
                command.destroy();
            } catch (Exception e) {
                log.warn("doCloseImmediately({}) failed ({}) to destroy command: {}",
                         this, e.getClass().getSimpleName(), e.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("doCloseImmediately(" + this + ") command destruction failure details", e);
                }
            } finally {
                command = null;
            }
        }

        IOException e = IoUtils.closeQuietly(remoteWindow, out, err, receiver);
        if (e != null) {
            if (log.isDebugEnabled()) {
                log.debug("doCloseImmediately({}) failed ({}) to close resources: {}",
                          this, e.getClass().getSimpleName(), e.getMessage());
            }

            if (log.isTraceEnabled()) {
                Throwable[] suppressed = e.getSuppressed();
                if (GenericUtils.length(suppressed) > 0) {
                    for (Throwable t : suppressed) {
                        log.trace("Suppressed " + t.getClass().getSimpleName() + ") while close immediately resource(s) of " + this + ": " + t.getMessage());
                    }
                }
            }
        }

        super.doCloseImmediately();
    }

    @Override
    public void handleEof() throws IOException {
        super.handleEof();

        IOException e = IoUtils.closeQuietly(receiver);
        if (e != null) {
            if (log.isDebugEnabled()) {
                log.debug("handleEof({}) failed ({}) to close receiver: {}",
                          this, e.getClass().getSimpleName(), e.getMessage());
            }
        }
    }

    @Override
    protected void doWriteData(byte[] data, int off, int len) throws IOException {
        // If we're already closing, ignore incoming data
        if (isClosing()) {
            return;
        }
        if (receiver != null) {
            int r = receiver.data(this, data, off, len);
            if (r > 0) {
                localWindow.consumeAndCheck(r);
            }
        } else {
            if (tempBuffer == null) {
                tempBuffer = new ByteArrayBuffer(len + Long.SIZE, false);
            }
            tempBuffer.putRawBytes(data, off, len);
        }
    }

    @Override
    protected void doWriteExtendedData(byte[] data, int off, int len) throws IOException {
        throw new UnsupportedOperationException("Server channel does not support extended data");
    }

    /**
     * @param type   The request type
     * @param buffer The {@link Buffer} containing extra request-specific content
     * @return A {@link Boolean} representing the success/failure of handling
     * the request - {@code null} if unknown request received
     * @throws IOException If request requires some extra response and failed
     *                     to generate it
     */
    public Boolean handleRequest(String type, Buffer buffer) throws IOException {
        switch (type) {
            case "env":
                return handleEnv(buffer);
            case "pty-req":
                return handlePtyReq(buffer);
            case "window-change":
                return handleWindowChange(buffer);
            case "signal":
                return handleSignal(buffer);
            case "break":
                return handleBreak(buffer);
            case "shell":
                if ((this.type == null) && handleShell(buffer)) {
                    this.type = type;
                    return Boolean.TRUE;
                } else {
                    return Boolean.FALSE;
                }
            case "exec":
                if ((this.type == null) && handleExec(buffer)) {
                    this.type = type;
                    return Boolean.TRUE;
                } else {
                    return Boolean.FALSE;
                }
            case "subsystem":
                if ((this.type == null) && handleSubsystem(buffer)) {
                    this.type = type;
                    return Boolean.TRUE;
                } else {
                    return Boolean.FALSE;
                }
            case "auth-agent-req@openssh.com":
                return handleAgentForwarding(buffer);
            case "x11-req":
                return handleX11Forwarding(buffer);
            default:
                return null;
        }
    }

    protected boolean handleEnv(Buffer buffer) throws IOException {
        String name = buffer.getString();
        String value = buffer.getString();
        addEnvVariable(name, value);
        if (log.isDebugEnabled()) {
            log.debug("handleEnv({}): {} = {}", this, name, value);
        }
        return true;
    }

    protected boolean handlePtyReq(Buffer buffer) throws IOException {
        String term = buffer.getString();
        int tColumns = buffer.getInt();
        int tRows = buffer.getInt();
        int tWidth = buffer.getInt();
        int tHeight = buffer.getInt();
        byte[] modes = buffer.getBytes();
        Environment environment = getEnvironment();
        Map<PtyMode, Integer> ptyModes = environment.getPtyModes();

        for (int i = 0; i < modes.length && (modes[i] != PtyMode.TTY_OP_END);) {
            int opcode = modes[i++] & 0x00FF;
            PtyMode mode = PtyMode.fromInt(opcode);
            /**
             * According to section 8 of RFC 4254:
             * "Opcodes 160 to 255 are not yet defined, and cause parsing to stop"
             */
            if (mode == null) {
                log.warn("handlePtyReq({}) unknown pty opcode value: {}", this, opcode);
                break;
            }
            int val = ((modes[i++] << 24) & 0xff000000)
                    | ((modes[i++] << 16) & 0x00ff0000)
                    | ((modes[i++] << 8) & 0x0000ff00)
                    | ((modes[i++]) & 0x000000ff);
            ptyModes.put(mode, val);
        }

        if (log.isDebugEnabled()) {
            log.debug("handlePtyReq({}): term={}, size=({} - {}), pixels=({}, {}), modes=[{}]",
                      this, term, tColumns, tRows, tWidth, tHeight, ptyModes);
        }

        addEnvVariable(Environment.ENV_TERM, term);
        addEnvVariable(Environment.ENV_COLUMNS, Integer.toString(tColumns));
        addEnvVariable(Environment.ENV_LINES, Integer.toString(tRows));
        return true;
    }

    protected boolean handleWindowChange(Buffer buffer) throws IOException {
        int tColumns = buffer.getInt();
        int tRows = buffer.getInt();
        int tWidth = buffer.getInt();
        int tHeight = buffer.getInt();
        if (log.isDebugEnabled()) {
            log.debug("handleWindowChange({}): ({} - {}), ({}, {})",
                      this, tColumns, tRows, tWidth, tHeight);
        }

        StandardEnvironment e = getEnvironment();
        e.set(Environment.ENV_COLUMNS, Integer.toString(tColumns));
        e.set(Environment.ENV_LINES, Integer.toString(tRows));
        e.signal(Signal.WINCH);
        return true;
    }

    protected boolean handleSignal(Buffer buffer) throws IOException {
        String name = buffer.getString();
        if (log.isDebugEnabled()) {
            log.debug("handleSignal({}): {}", this, name);
        }

        Signal signal = Signal.get(name);
        if (signal != null) {
            getEnvironment().signal(signal);
        } else {
            log.warn("handleSignal({}) unknown signal received: {}", this, name);
        }
        return true;
    }

    protected boolean handleBreak(Buffer buffer) throws IOException {
        String name = buffer.getString();
        if (log.isDebugEnabled()) {
            log.debug("handleBreak({}) {}", this, name);
        }

        getEnvironment().signal(Signal.INT);
        return true;
    }

    protected boolean handleShell(Buffer buffer) throws IOException {
        // If we're already closing, ignore incoming data
        if (isClosing()) {
            if (log.isDebugEnabled()) {
                log.debug("handleShell({}) - closing", this);
            }
            return false;
        }

        ServerFactoryManager manager = ((ServerSession) getSession()).getFactoryManager();
        Factory<Command> factory = manager.getShellFactory();
        if (factory == null) {
            if (log.isDebugEnabled()) {
                log.debug("handleShell({}) - no shell factory", this);
            }
            return false;
        }

        command = factory.create();
        if (command == null) {
            if (log.isDebugEnabled()) {
                log.debug("handleShell({}) - no shell command", this);
            }
            return false;
        }

        prepareCommand();
        command.start(getEnvironment());
        return true;
    }

    protected boolean handleExec(Buffer buffer) throws IOException {
        // If we're already closing, ignore incoming data
        if (isClosing()) {
            return false;
        }

        String commandLine = buffer.getString();
        ServerFactoryManager manager = ((ServerSession) getSession()).getFactoryManager();
        CommandFactory factory = manager.getCommandFactory();
        if (factory == null) {
            log.warn("handleExec({}) No command factory for command: {}", this, commandLine);
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("handleExec({}) Executing command: {}", this, commandLine);
        }

        try {
            command = factory.createCommand(commandLine);
        } catch (RuntimeException e) {
            log.warn("handleExec({}) Failed ({}) to create command for {}: {}",
                     this, e.getClass().getSimpleName(), commandLine, e.getMessage());
            return false;
        }

        prepareCommand();
        // Launch command
        command.start(getEnvironment());
        return true;
    }

    protected boolean handleSubsystem(Buffer buffer) throws IOException {
        String subsystem = buffer.getString();
        ServerFactoryManager manager = ((ServerSession) getSession()).getFactoryManager();
        List<NamedFactory<Command>> factories = manager.getSubsystemFactories();
        if (GenericUtils.isEmpty(factories)) {
            log.warn("handleSubsystem({}) No factories for subsystem: {}", this, subsystem);
            return false;
        }

        command = NamedFactory.Utils.create(factories, subsystem);
        if (command == null) {
            log.warn("handleSubsystem({}) Unsupported subsystem: {}", this, subsystem);
            return false;
        }

        prepareCommand();
        // Launch command
        command.start(getEnvironment());
        return true;
    }

    /**
     * For {@link Command} to install {@link ChannelDataReceiver}.
     * When you do this, {@link Command#setInputStream(java.io.InputStream)} or
     * {@link org.apache.sshd.server.AsyncCommand#setIoInputStream(org.apache.sshd.common.io.IoInputStream)}
     * will no longer be invoked. If you call this method from {@link Command#start(Environment)},
     * the input stream you received in {@link Command#setInputStream(java.io.InputStream)} will
     * not read any data.
     *
     * @param receiver The {@link ChannelDataReceiver} instance
     */
    public void setDataReceiver(ChannelDataReceiver receiver) {
        this.receiver = receiver;
    }

    protected void prepareCommand() throws IOException {
        // Add the user
        Session session = getSession();
        addEnvVariable(Environment.ENV_USER, session.getUsername());
        // If the shell wants to be aware of the session, let's do that
        if (command instanceof SessionAware) {
            ((SessionAware) command).setSession((ServerSession) session);
        }
        if (command instanceof ChannelSessionAware) {
            ((ChannelSessionAware) command).setChannelSession(this);
        }
        // If the shell wants to be aware of the file system, let's do that too
        if (command instanceof FileSystemAware) {
            ServerFactoryManager manager = ((ServerSession) session).getFactoryManager();
            FileSystemFactory factory = manager.getFileSystemFactory();
            ((FileSystemAware) command).setFileSystem(factory.createFileSystem(session));
        }
        // If the shell wants to use non-blocking io
        if (command instanceof AsyncCommand) {
            asyncOut = new ChannelAsyncOutputStream(this, SshConstants.SSH_MSG_CHANNEL_DATA);
            asyncErr = new ChannelAsyncOutputStream(this, SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA);
            ((AsyncCommand) command).setIoOutputStream(asyncOut);
            ((AsyncCommand) command).setIoErrorStream(asyncErr);
        } else {
            out = new ChannelOutputStream(this, remoteWindow, log, SshConstants.SSH_MSG_CHANNEL_DATA);
            err = new ChannelOutputStream(this, remoteWindow, log, SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA);
            if (log.isTraceEnabled()) {
                // Wrap in logging filters
                String channelId = toString();
                out = new LoggingFilterOutputStream(out, "OUT(" + channelId + ")", log);
                err = new LoggingFilterOutputStream(err, "ERR(" + channelId + ")", log);
            }
            command.setOutputStream(out);
            command.setErrorStream(err);
        }
        if (this.receiver == null) {
            // if the command hasn't installed any ChannelDataReceiver, install the default
            // and give the command an InputStream
            if (command instanceof AsyncCommand) {
                AsyncDataReceiver recv = new AsyncDataReceiver(this);
                setDataReceiver(recv);
                ((AsyncCommand) command).setIoInputStream(recv.getIn());
            } else {
                PipeDataReceiver recv = new PipeDataReceiver(this, localWindow);
                setDataReceiver(recv);
                command.setInputStream(recv.getIn());
            }
        }
        if (tempBuffer != null) {
            Buffer buffer = tempBuffer;
            tempBuffer = null;
            doWriteData(buffer.array(), buffer.rpos(), buffer.available());
        }
        command.setExitCallback(new ExitCallback() {
            @Override
            public void onExit(int exitValue) {
                onExit(exitValue, "");
            }

            @Override
            @SuppressWarnings("synthetic-access")
            public void onExit(int exitValue, String exitMessage) {
                try {
                    closeShell(exitValue);
                    if (log.isDebugEnabled()) {
                        log.debug("onExit({}) code={} message='{}' shell closed", ChannelSession.this, exitValue, exitMessage);
                    }
                } catch (IOException e) {
                    log.warn("onExit({}) code={} message='{}' {} closing shell: {}",
                             ChannelSession.this, exitValue, exitMessage, e.getClass().getSimpleName(), e.getMessage());
                }
            }
        });
    }

    protected int getPtyModeValue(PtyMode mode) {
        Number v = getEnvironment().getPtyModes().get(mode);
        return v != null ? v.intValue() : 0;
    }

    protected boolean handleAgentForwarding(Buffer buffer) throws IOException {
        Session session = getSession();
        ValidateUtils.checkTrue(session instanceof ServerSession, "Session not a server one");

        FactoryManager manager = session.getFactoryManager();
        ForwardingFilter filter = manager.getTcpipForwardingFilter();
        SshAgentFactory factory = manager.getAgentFactory();
        if ((factory == null) || (filter == null) || (!filter.canForwardAgent(session))) {
            if (log.isDebugEnabled()) {
                log.debug("handleAgentForwarding(" + this + ")[haveFactory=" + (factory != null) + ",haveFilter=" + (filter != null) + "] filtered out");
            }
            return false;
        }

        String authSocket = service.initAgentForward();
        addEnvVariable(SshAgent.SSH_AUTHSOCKET_ENV_NAME, authSocket);
        return true;
    }

    protected boolean handleX11Forwarding(Buffer buffer) throws IOException {
        Session session = getSession();
        ValidateUtils.checkTrue(session instanceof ServerSession, "Session not a server one");

        FactoryManager manager = session.getFactoryManager();
        ForwardingFilter filter = manager.getTcpipForwardingFilter();
        if ((filter == null) || (!filter.canForwardX11(session))) {
            if (log.isDebugEnabled()) {
                log.debug("handleX11Forwarding(" + this + ")[haveFilter=" + (filter != null) + "] filtered out");
            }
            return false;
        }

        boolean singleConnection = buffer.getBoolean();
        String authProtocol = buffer.getString();
        String authCookie = buffer.getString();
        int screenId = buffer.getInt();
        String display = service.createX11Display(singleConnection, authProtocol, authCookie, screenId);
        if (GenericUtils.isEmpty(display)) {
            if (log.isDebugEnabled()) {
                log.debug("handleX11Forwarding(" + this + ") no X.11 display created");
            }
            return false;
        }

        addEnvVariable(X11ForwardSupport.ENV_DISPLAY, display);
        return true;
    }

    protected void addEnvVariable(String name, String value) {
        getEnvironment().set(name, value);
    }

    public StandardEnvironment getEnvironment() {
        return env;
    }

    protected void closeShell(int exitValue) throws IOException {
        if (!isClosing()) {
            sendEof();
            sendExitStatus(exitValue);
            commandExitFuture.setClosed();
            close(false);
        } else {
            commandExitFuture.setClosed();
        }
    }

    private class ChannelSessionRequestHandler extends AbstractChannelRequestHandler {
        ChannelSessionRequestHandler() {
            super();
        }

        @Override
        public Result process(Channel channel, String request, boolean wantReply, Buffer buffer) throws Exception {
            Boolean r = handleRequest(request, buffer);
            if (r == null) {
                return Result.Unsupported;
            } else {
                return r ? Result.ReplySuccess : Result.ReplyFailure;
            }
        }
    }
}
