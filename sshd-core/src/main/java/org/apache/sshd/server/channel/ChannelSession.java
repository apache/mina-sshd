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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TimerTask;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.agent.common.AgentForwardSupport;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelAsyncOutputStream;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.channel.ChannelRequestHandler;
import org.apache.sshd.common.channel.PtyMode;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.channel.RequestHandler.Result;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.file.FileSystemAware;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoWriteFuture;
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
    public static final List<ChannelRequestHandler> DEFAULT_HANDLERS =
            Collections.unmodifiableList(
                    Arrays.<ChannelRequestHandler>asList(PuttyRequestHandler.INSTANCE));

    protected String type;
    protected ChannelAsyncOutputStream asyncOut;
    protected ChannelAsyncOutputStream asyncErr;
    protected OutputStream out;
    protected OutputStream err;
    protected Command commandInstance;
    protected ChannelDataReceiver receiver;
    protected Buffer tempBuffer;
    protected final AtomicBoolean commandStarted = new AtomicBoolean(false);
    protected final StandardEnvironment env = new StandardEnvironment();
    protected final CloseFuture commandExitFuture = new DefaultCloseFuture(lock);

    public ChannelSession() {
        this(DEFAULT_HANDLERS);
    }

    public ChannelSession(Collection<? extends RequestHandler<Channel>> handlers) {
        super(handlers);
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
        public CommandCloseable() {
            super();
        }

        @Override
        public boolean isClosed() {
            return commandExitFuture.isClosed();
        }

        @Override
        public boolean isClosing() {
            return isClosed();
        }

        @Override
        public void addCloseFutureListener(SshFutureListener<CloseFuture> listener) {
            commandExitFuture.addListener(listener);
        }

        @Override
        public void removeCloseFutureListener(SshFutureListener<CloseFuture> listener) {
            commandExitFuture.removeListener(listener);
        }

        @Override
        public CloseFuture close(boolean immediately) {
            if (immediately || (commandInstance == null)) {
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
        if (commandInstance != null) {
            try {
                commandInstance.destroy();
            } catch (Throwable e) {
                log.warn("doCloseImmediately({}) failed ({}) to destroy command: {}",
                         this, e.getClass().getSimpleName(), e.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("doCloseImmediately(" + this + ") command destruction failure details", e);
                }
            } finally {
                commandInstance = null;
            }
        }

        IOException e = IoUtils.closeQuietly(getRemoteWindow(), out, err, receiver);
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

            if (log.isTraceEnabled()) {
                log.trace("handleEof(" + this + ") receiver close failure details", e);
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
                Window wLocal = getLocalWindow();
                wLocal.consumeAndCheck(r);
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

    @Override
    protected RequestHandler.Result handleInternalRequest(String requestType, boolean wantReply, Buffer buffer) throws IOException {
        switch (requestType) {
            case "env":
                return handleEnv(buffer, wantReply);
            case "pty-req":
                return handlePtyReq(buffer, wantReply);
            case "window-change":
                return handleWindowChange(buffer, wantReply);
            case "signal":
                return handleSignal(buffer, wantReply);
            case "break":
                return handleBreak(buffer, wantReply);
            case Channel.CHANNEL_SHELL:
                if (this.type == null) {
                    RequestHandler.Result r = handleShell(requestType, buffer, wantReply);
                    if (RequestHandler.Result.ReplySuccess.equals(r) || RequestHandler.Result.Replied.equals(r)) {
                        this.type = requestType;
                    }
                    return r;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("handleInternalRequest({})[want-reply={}] type already set for request={}: {}",
                                  this, wantReply, requestType, this.type);
                    }
                    return RequestHandler.Result.ReplyFailure;
                }
            case Channel.CHANNEL_EXEC:
                if (this.type == null) {
                    RequestHandler.Result r = handleExec(requestType, buffer, wantReply);
                    if (RequestHandler.Result.ReplySuccess.equals(r) || RequestHandler.Result.Replied.equals(r)) {
                        this.type = requestType;
                    }
                    return r;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("handleInternalRequest({})[want-reply={}] type already set for request={}: {}",
                                  this, wantReply, requestType, this.type);
                    }
                    return RequestHandler.Result.ReplyFailure;
                }
            case Channel.CHANNEL_SUBSYSTEM:
                if (this.type == null) {
                    RequestHandler.Result r = handleSubsystem(requestType, buffer, wantReply);
                    if (RequestHandler.Result.ReplySuccess.equals(r) || RequestHandler.Result.Replied.equals(r)) {
                        this.type = requestType;
                    }
                    return r;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("handleInternalRequest({})[want-reply={}] type already set for request={}: {}",
                                  this, wantReply, requestType, this.type);
                    }
                    return RequestHandler.Result.ReplyFailure;
                }
            case "auth-agent-req@openssh.com":
                return handleAgentForwarding(buffer, wantReply);
            case "x11-req":
                return handleX11Forwarding(buffer, wantReply);
            default:
                return super.handleInternalRequest(requestType, wantReply, buffer);
        }
    }

    @Override
    protected IoWriteFuture sendResponse(Buffer buffer, String req, Result result, boolean wantReply) throws IOException {
        IoWriteFuture future = super.sendResponse(buffer, req, result, wantReply);
        if (!RequestHandler.Result.ReplySuccess.equals(result)) {
            return future;
        }

        if (commandInstance == null) {
            if (log.isDebugEnabled()) {
                log.debug("sendResponse({}) request={} no pending command", this, req);
            }
            return future; // no pending command to activate
        }

        if (!Objects.equals(this.type, req)) {
            if (log.isDebugEnabled()) {
                log.debug("sendResponse({}) request={} mismatched channel type: {}", this, req, this.type);
            }
            return future; // request does not match the current channel type
        }

        if (commandStarted.getAndSet(true)) {
            if (log.isDebugEnabled()) {
                log.debug("sendResponse({}) request={} pending command already started", this, req);
            }
            return future;
        }

        // TODO - consider if (Channel.CHANNEL_SHELL.equals(req) || Channel.CHANNEL_EXEC.equals(req) || Channel.CHANNEL_SUBSYSTEM.equals(req)) {
        if (log.isDebugEnabled()) {
            log.debug("sendResponse({}) request={} activate command", this, req);
        }
        commandInstance.start(getEnvironment());
        return future;
    }

    protected RequestHandler.Result handleEnv(Buffer buffer, boolean wantReply) throws IOException {
        String name = buffer.getString();
        String value = buffer.getString();
        addEnvVariable(name, value);
        if (log.isDebugEnabled()) {
            log.debug("handleEnv({}): {} = {}", this, name, value);
        }
        return RequestHandler.Result.ReplySuccess;
    }

    protected RequestHandler.Result handlePtyReq(Buffer buffer, boolean wantReply) throws IOException {
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
            /*
             * According to section 8 of RFC 4254:
             *
             *      "Opcodes 160 to 255 are not yet defined, and cause parsing to stop"
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
        return RequestHandler.Result.ReplySuccess;
    }

    protected RequestHandler.Result handleWindowChange(Buffer buffer, boolean wantReply) throws IOException {
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
        return RequestHandler.Result.ReplySuccess;
    }

    // see RFC4254 section 6.10
    protected RequestHandler.Result handleSignal(Buffer buffer, boolean wantReply) throws IOException {
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
        return RequestHandler.Result.ReplySuccess;
    }

    // see rfc4335
    protected RequestHandler.Result handleBreak(Buffer buffer, boolean wantReply) throws IOException {
        long breakLength = buffer.getUInt();
        if (log.isDebugEnabled()) {
            log.debug("handleBreak({}) length={}", this, breakLength);
        }

        getEnvironment().signal(Signal.INT);
        return RequestHandler.Result.ReplySuccess;
    }

    protected RequestHandler.Result handleShell(String request, Buffer buffer, boolean wantReply) throws IOException {
        // If we're already closing, ignore incoming data
        if (isClosing()) {
            if (log.isDebugEnabled()) {
                log.debug("handleShell({}) - closing", this);
            }
            return RequestHandler.Result.ReplyFailure;
        }

        ServerFactoryManager manager = ValidateUtils.checkNotNull(getServerSession(), "No server session").getFactoryManager();
        Factory<Command> factory = ValidateUtils.checkNotNull(manager, "No server factory manager").getShellFactory();
        if (factory == null) {
            if (log.isDebugEnabled()) {
                log.debug("handleShell({}) - no shell factory", this);
            }
            return RequestHandler.Result.ReplyFailure;
        }

        try {
            commandInstance = factory.create();
        } catch (RuntimeException | Error e) {
            log.warn("handleShell({}) Failed ({}) to create shell: {}",
                     this, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("handleShell(" + this + ") shell creation failure details", e);
            }
            return RequestHandler.Result.ReplyFailure;
        }

        if (commandInstance == null) {
            if (log.isDebugEnabled()) {
                log.debug("handleShell({}) - no shell command", this);
            }
            return RequestHandler.Result.ReplyFailure;
        }

        return prepareChannelCommand(request, commandInstance);
    }

    protected RequestHandler.Result handleExec(String request, Buffer buffer, boolean wantReply) throws IOException {
        // If we're already closing, ignore incoming data
        if (isClosing()) {
            return RequestHandler.Result.ReplyFailure;
        }

        String commandLine = buffer.getString();
        ServerFactoryManager manager = ValidateUtils.checkNotNull(getServerSession(), "No server session").getFactoryManager();
        CommandFactory factory = ValidateUtils.checkNotNull(manager, "No server factory manager").getCommandFactory();
        if (factory == null) {
            log.warn("handleExec({}) No command factory for command: {}", this, commandLine);
            return RequestHandler.Result.ReplyFailure;
        }

        if (log.isDebugEnabled()) {
            log.debug("handleExec({}) Executing command: {}", this, commandLine);
        }

        try {
            commandInstance = factory.createCommand(commandLine);
        } catch (RuntimeException | Error e) {
            log.warn("handleExec({}) Failed ({}) to create command for {}: {}",
                     this, e.getClass().getSimpleName(), commandLine, e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("handleExec(" + this + ") command=" + commandLine + " creation failure details", e);
            }

            return RequestHandler.Result.ReplyFailure;
        }

        if (commandInstance == null) {
            log.warn("handleExec({}) Unsupported command: {}", this, commandLine);
            return RequestHandler.Result.ReplyFailure;
        }

        return prepareChannelCommand(request, commandInstance);
    }

    protected RequestHandler.Result handleSubsystem(String request, Buffer buffer, boolean wantReply) throws IOException {
        String subsystem = buffer.getString();
        if (log.isDebugEnabled()) {
            log.debug("handleSubsystem({})[want-reply={}] sybsystem={}",
                      this, wantReply, subsystem);
        }

        ServerFactoryManager manager = ValidateUtils.checkNotNull(getServerSession(), "No server session").getFactoryManager();
        List<NamedFactory<Command>> factories = ValidateUtils.checkNotNull(manager, "No server factory manager").getSubsystemFactories();
        if (GenericUtils.isEmpty(factories)) {
            log.warn("handleSubsystem({}) No factories for subsystem: {}", this, subsystem);
            return RequestHandler.Result.ReplyFailure;
        }

        try {
            commandInstance = NamedFactory.Utils.create(factories, subsystem);
        } catch (RuntimeException | Error e) {
            log.warn("handleSubsystem({}) Failed ({}) to create command for subsystem={}: {}",
                      this, e.getClass().getSimpleName(), subsystem, e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("handleSubsystem(" + this + ") subsystem=" + subsystem + " creation failure details", e);
            }
            return RequestHandler.Result.ReplyFailure;
        }

        if (commandInstance == null) {
            log.warn("handleSubsystem({}) Unsupported subsystem: {}", this, subsystem);
            return RequestHandler.Result.ReplyFailure;
        }

        return prepareChannelCommand(request, commandInstance);
    }

    protected RequestHandler.Result prepareChannelCommand(String request, Command cmd) throws IOException {
        Command command = prepareCommand(request, cmd);
        if (command == null) {
            log.warn("prepareChannelCommand({})[{}] no command prepared", this, request);
            return RequestHandler.Result.ReplyFailure;
        }

        if (command != cmd) {
            if (log.isDebugEnabled()) {
                log.debug("prepareChannelCommand({})[{}] replaced original command", this, request);
            }
            commandInstance = command;
        }

        if (log.isDebugEnabled()) {
            log.debug("prepareChannelCommand({})[{}] prepared command", this, request);
        }
        return RequestHandler.Result.ReplySuccess;
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

    /**
     * Called by {@link #prepareChannelCommand(String, Command)} in order to set
     * up the command's streams, session, file-system, exit callback, etc..
     *
     * @param requestType The request that caused the command to be created
     * @param command The created {@link Command} - may be {@code null}
     * @return The updated command instance - if {@code null} then the request that
     * initially caused the creation of the command is failed and the original command
     * (if any) destroyed (eventually). <B>Note:</B> if a different command instance
     * than the input one is returned, then it is up to the implementor to take care
     * of the wrapping or destruction of the original command instance.
     * @throws IOException If failed to prepare the command
     */
    protected Command prepareCommand(String requestType, Command command) throws IOException {
        if (command == null) {
            return null;
        }
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
            Window wRemote = getRemoteWindow();
            out = new ChannelOutputStream(this, wRemote, log, SshConstants.SSH_MSG_CHANNEL_DATA, false);
            err = new ChannelOutputStream(this, wRemote, log, SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA, false);
            if (log.isTraceEnabled()) {
                // Wrap in logging filters
                out = new LoggingFilterOutputStream(out, "OUT(" + this + ")", log, this);
                err = new LoggingFilterOutputStream(err, "ERR(" + this + ")", log, this);
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
                PipeDataReceiver recv = new PipeDataReceiver(this, getLocalWindow());
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

        return command;
    }

    protected int getPtyModeValue(PtyMode mode) {
        Number v = getEnvironment().getPtyModes().get(mode);
        return v != null ? v.intValue() : 0;
    }

    protected RequestHandler.Result handleAgentForwarding(Buffer buffer, boolean wantReply) throws IOException {
        ServerSession session = getServerSession();
        FactoryManager manager = ValidateUtils.checkNotNull(session.getFactoryManager(), "No session factory manager");
        ForwardingFilter filter = manager.getTcpipForwardingFilter();
        SshAgentFactory factory = manager.getAgentFactory();
        try {
            if ((factory == null) || (filter == null) || (!filter.canForwardAgent(session))) {
                if (log.isDebugEnabled()) {
                    log.debug("handleAgentForwarding(" + this + ")[haveFactory=" + (factory != null) + ",haveFilter=" + (filter != null) + "] filtered out");
                }
                return RequestHandler.Result.ReplyFailure;
            }
        } catch (Error e) {
            log.warn("handleAgentForwarding({}) failed ({}) to consult forwarding filter: {}",
                     this, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("handleAgentForwarding(" + this + ") filter consultation failure details", e);
            }
            throw new RuntimeSshException(e);
        }

        AgentForwardSupport agentForward = service.getAgentForwardSupport();
        if (agentForward == null) {
            if (log.isDebugEnabled()) {
                log.debug("handleAgentForwarding() no agent forward support", this);
            }
            return RequestHandler.Result.ReplyFailure;
        }

        String authSocket = agentForward.initialize();
        addEnvVariable(SshAgent.SSH_AUTHSOCKET_ENV_NAME, authSocket);
        return RequestHandler.Result.ReplySuccess;
    }

    protected RequestHandler.Result handleX11Forwarding(Buffer buffer, boolean wantReply) throws IOException {
        ServerSession session = getServerSession();
        boolean singleConnection = buffer.getBoolean();
        String authProtocol = buffer.getString();
        String authCookie = buffer.getString();
        int screenId = buffer.getInt();

        FactoryManager manager = ValidateUtils.checkNotNull(session.getFactoryManager(), "No factory manager");
        ForwardingFilter filter = manager.getTcpipForwardingFilter();
        try {
            if ((filter == null) || (!filter.canForwardX11(session))) {
                if (log.isDebugEnabled()) {
                    log.debug("handleX11Forwarding({}) single={}, protocol={}, cookie={}, screen={}, filter={}: filtered",
                              this, singleConnection, authProtocol, authCookie, screenId, filter);
                }
                return RequestHandler.Result.ReplyFailure;
            }
        } catch (Error e) {
            log.warn("handleX11Forwarding({}) failed ({}) to consult forwarding filter: {}",
                     this, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("handleX11Forwarding(" + this + ") filter consultation failure details", e);
            }
            throw new RuntimeSshException(e);
        }

        X11ForwardSupport x11Forward = service.getX11ForwardSupport();
        if (x11Forward == null) {
            if (log.isDebugEnabled()) {
                log.debug("handleX11Forwarding({}) single={}, protocol={}, cookie={}, screen={} - no forwarder'",
                          this, singleConnection, authProtocol, authCookie, screenId);
            }
            return RequestHandler.Result.ReplyFailure;
        }

        String display = x11Forward.createDisplay(singleConnection, authProtocol, authCookie, screenId);
        if (log.isDebugEnabled()) {
            log.debug("handleX11Forwarding({}) single={}, protocol={}, cookie={}, screen={} - display='{}'",
                      this, singleConnection, authProtocol, authCookie, screenId, display);
        }
        if (GenericUtils.isEmpty(display)) {
            return RequestHandler.Result.ReplyFailure;
        }

        addEnvVariable(X11ForwardSupport.ENV_DISPLAY, display);
        return RequestHandler.Result.ReplySuccess;
    }

    protected void addEnvVariable(String name, String value) {
        getEnvironment().set(name, value);
    }

    public StandardEnvironment getEnvironment() {
        return env;
    }

    protected void closeShell(int exitValue) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("closeShell({}) exit code={}", this, exitValue);
        }

        if (!isClosing()) {
            sendEof();
            sendExitStatus(exitValue);
            commandExitFuture.setClosed();
            close(false);
        } else {
            commandExitFuture.setClosed();
        }
    }
}
