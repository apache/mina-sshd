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
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
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
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelAsyncOutputStream;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.channel.ChannelRequestHandler;
import org.apache.sshd.common.channel.PtyMode;
import org.apache.sshd.common.channel.RequestHandler;
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
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.ChannelSessionAware;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.SessionAware;
import org.apache.sshd.server.Signal;
import org.apache.sshd.server.StandardEnvironment;
import org.apache.sshd.server.command.AsyncCommand;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.command.CommandFactory;
import org.apache.sshd.server.forward.AgentForwardingFilter;
import org.apache.sshd.server.forward.X11ForwardingFilter;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.shell.ShellFactory;
import org.apache.sshd.server.subsystem.SubsystemFactory;
import org.apache.sshd.server.x11.X11ForwardSupport;

/**
 * Server side channel session
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelSession extends AbstractServerChannel {
    public static final List<ChannelRequestHandler> DEFAULT_HANDLERS = Collections.singletonList(PuttyRequestHandler.INSTANCE);

    protected String type;
    protected ChannelAsyncOutputStream asyncOut;
    protected ChannelAsyncOutputStream asyncErr;
    protected OutputStream out;
    protected OutputStream err;
    protected Command commandInstance;
    protected ChannelDataReceiver receiver;
    protected ChannelDataReceiver extendedDataWriter;
    protected Buffer receiverBuffer;
    protected Buffer extendedDataBuffer;
    protected final AtomicBoolean commandStarted = new AtomicBoolean(false);
    protected final StandardEnvironment env = new StandardEnvironment();
    protected final CloseFuture commandExitFuture;

    public ChannelSession() {
        this(DEFAULT_HANDLERS);
    }

    public ChannelSession(Collection<? extends RequestHandler<Channel>> handlers) {
        super("", handlers, null);

        commandExitFuture = new DefaultCloseFuture(getClass().getSimpleName(), futureLock);
    }

    @Override
    public ServerSession getSession() {
        return (ServerSession) super.getSession();
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
                .sequential(new CommandCloseable(), super.getInnerCloseable())
                .parallel(asyncOut, asyncErr)
                .run(toString(), this::closeImmediately0)
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
                IOException e = IoUtils.closeQuietly(receiver, extendedDataWriter);
                boolean debugEnabled = log.isDebugEnabled();
                if (e != null) {
                    if (debugEnabled) {
                        log.debug("close({})[immediately={}] failed ({}) to close receiver(s): {}",
                                this, immediately, e.getClass().getSimpleName(), e.getMessage());
                    }
                }

                TimerTask task = new TimerTask() {
                    @Override
                    public void run() {
                        commandExitFuture.setClosed();
                    }
                };

                ChannelSession channel = ChannelSession.this;
                Duration timeout = CoreModuleProperties.COMMAND_EXIT_TIMEOUT.getRequired(channel);
                if (debugEnabled) {
                    log.debug("Wait {} ms for shell to exit cleanly on {}", timeout, channel);
                }

                Session s = channel.getSession();
                FactoryManager manager = Objects.requireNonNull(s.getFactoryManager(), "No factory manager");
                ScheduledExecutorService scheduler
                        = Objects.requireNonNull(manager.getScheduledExecutorService(), "No scheduling service");
                scheduler.schedule(task, timeout.toMillis(), TimeUnit.MILLISECONDS);
                commandExitFuture.addListener(future -> task.cancel());
            }
            return commandExitFuture;
        }
    }

    protected void closeImmediately0() {
        if (commandInstance != null) {
            try {
                commandInstance.destroy(this);
            } catch (Throwable e) {
                warn("doCloseImmediately({}) failed ({}) to destroy command: {}",
                        this, e.getClass().getSimpleName(), e.getMessage(), e);
            } finally {
                commandInstance = null;
            }
        }

        IOException e = IoUtils.closeQuietly(getRemoteWindow(), out, err, receiver, extendedDataWriter);
        if (e != null) {
            debug("doCloseImmediately({}) failed ({}) to close resources: {}",
                    this, e.getClass().getSimpleName(), e.getMessage(), e);
        }
    }

    @Override
    public void handleEof() throws IOException {
        super.handleEof();

        IOException e = IoUtils.closeQuietly(receiver, extendedDataWriter);
        if (e != null) {
            debug("handleEof({}) failed ({}) to close receiver(s): {}",
                    this, e.getClass().getSimpleName(), e.getMessage(), e);
        }
    }

    @Override
    protected void doWriteData(byte[] data, int off, long len) throws IOException {
        // If we're already closing, ignore incoming data
        if (isClosing()) {
            return;
        }
        ValidateUtils.checkTrue(len <= Integer.MAX_VALUE,
                "Data length exceeds int boundaries: %d", len);

        int reqLen = (int) len;
        if (receiver != null) {
            int r = receiver.data(this, data, off, reqLen);
            if (r > 0) {
                Window wLocal = getLocalWindow();
                wLocal.consumeAndCheck(r);
            }
        } else {
            ValidateUtils.checkTrue(len <= (Integer.MAX_VALUE - Long.SIZE),
                    "Temporary data length exceeds int boundaries: %d", len);
            if (receiverBuffer == null) {
                receiverBuffer = new ByteArrayBuffer(reqLen + Long.SIZE, false);
            }
            receiverBuffer.putRawBytes(data, off, reqLen);
        }
    }

    @Override
    protected void doWriteExtendedData(byte[] data, int off, long len) throws IOException {
        ValidateUtils.checkTrue(len <= (Integer.MAX_VALUE - Long.SIZE),
                "Extended data length exceeds int boundaries: %d", len);

        if (extendedDataWriter != null) {
            extendedDataWriter.data(this, data, off, (int) len);
            return;
        }

        int reqSize = (int) len;
        int maxBufSize = CoreModuleProperties.MAX_EXTDATA_BUFSIZE.getRequired(this);
        int curBufSize = (extendedDataBuffer == null) ? 0 : extendedDataBuffer.available();
        int totalSize = curBufSize + reqSize;
        if (totalSize > maxBufSize) {
            if ((curBufSize <= 0) && (maxBufSize <= 0)) {
                throw new UnsupportedOperationException("Session channel does not support extended data");
            }

            throw new IndexOutOfBoundsException("Extended data buffer size (" + maxBufSize + ") exceeded");
        }

        if (extendedDataBuffer == null) {
            extendedDataBuffer = new ByteArrayBuffer(totalSize + Long.SIZE, false);
        }
        extendedDataBuffer.putRawBytes(data, off, reqSize);
    }

    @Override
    protected RequestHandler.Result handleInternalRequest(
            String requestType, boolean wantReply, Buffer buffer)
            throws IOException {
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
                    if (RequestHandler.Result.ReplySuccess.equals(r)
                            || RequestHandler.Result.Replied.equals(r)) {
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
                    if (RequestHandler.Result.ReplySuccess.equals(r)
                            || RequestHandler.Result.Replied.equals(r)) {
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
                    if (RequestHandler.Result.ReplySuccess.equals(r)
                            || RequestHandler.Result.Replied.equals(r)) {
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
            case "auth-agent-req": // see https://tools.ietf.org/html/draft-ietf-secsh-agent-02
            case "auth-agent-req@openssh.com":
                return handleAgentForwarding(requestType, buffer, wantReply);
            case "x11-req":
                return handleX11Forwarding(requestType, buffer, wantReply);
            default:
                return super.handleInternalRequest(requestType, wantReply, buffer);
        }
    }

    @Override
    protected IoWriteFuture sendResponse(
            Buffer buffer, String req, RequestHandler.Result result, boolean wantReply)
            throws IOException {
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

        /*
         * TODO - consider if (Channel.CHANNEL_SHELL.equals(req) || Channel.CHANNEL_EXEC.equals(req) ||
         * Channel.CHANNEL_SUBSYSTEM.equals(req)) {
         */
        if (log.isDebugEnabled()) {
            log.debug("sendResponse({}) request={} activate command", this, req);
        }
        commandInstance.start(this, getEnvironment());
        return future;
    }

    protected RequestHandler.Result handleEnv(Buffer buffer, boolean wantReply) throws IOException {
        String name = buffer.getString();
        String value = buffer.getString();
        if (log.isDebugEnabled()) {
            log.debug("handleEnv({}): {} = {}", this, name, value);
        }
        return handleEnvParsed(name, value);
    }

    protected RequestHandler.Result handleEnvParsed(String name, String value) throws IOException {
        addEnvVariable(name, value);
        return RequestHandler.Result.ReplySuccess;
    }

    protected RequestHandler.Result handlePtyReq(Buffer buffer, boolean wantReply) throws IOException {
        String term = buffer.getString();
        int tColumns = buffer.getInt();
        int tRows = buffer.getInt();
        int tWidth = buffer.getInt();
        int tHeight = buffer.getInt();
        byte[] modes = buffer.getBytes();

        Map<PtyMode, Integer> ptyModes = new HashMap<>();
        for (int i = 0; (i < modes.length) && (modes[i] != PtyMode.TTY_OP_END);) {
            int opcode = modes[i++] & 0x00FF;
            /*
             * According to https://tools.ietf.org/html/rfc4254#section-8:
             *
             * Opcodes 160 to 255 are not yet defined, and cause parsing to stop
             */
            if ((opcode >= 160) && (opcode <= 255)) {
                log.warn("handlePtyReq({}) unknown reserved pty opcode value: {}", this, opcode);
                break;
            }

            int val = ((modes[i++] << 24) & 0xff000000)
                      | ((modes[i++] << 16) & 0x00ff0000)
                      | ((modes[i++] << 8) & 0x0000ff00)
                      | ((modes[i++]) & 0x000000ff);
            PtyMode mode = PtyMode.fromInt(opcode);
            if (mode == null) {
                log.warn("handlePtyReq({}) unsupported pty opcode value: {}={}", this, opcode, val);
            } else {
                ptyModes.put(mode, val);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("handlePtyReq({}): term={}, size=({} - {}), pixels=({}, {}), modes=[{}]",
                    this, term, tColumns, tRows, tWidth, tHeight, ptyModes);
        }

        return handlePtyReqParsed(term, tColumns, tRows, tWidth, tHeight, ptyModes);
    }

    protected RequestHandler.Result handlePtyReqParsed(
            String term, int tColumns, int tRows, int tWidth, int tHeight,
            Map<PtyMode, Integer> ptyModes)
            throws IOException {
        Environment environment = getEnvironment();
        environment.getPtyModes().putAll(ptyModes);
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

        return handleWindowChangeParsed(tColumns, tRows, tWidth, tHeight);
    }

    protected RequestHandler.Result handleWindowChangeParsed(
            int tColumns, int tRows, int tWidth, int tHeight)
            throws IOException {
        StandardEnvironment e = getEnvironment();
        e.set(Environment.ENV_COLUMNS, Integer.toString(tColumns));
        e.set(Environment.ENV_LINES, Integer.toString(tRows));
        e.signal(this, Signal.WINCH);
        return RequestHandler.Result.ReplySuccess;
    }

    // see RFC4254 section 6.10
    protected RequestHandler.Result handleSignal(Buffer buffer, boolean wantReply) throws IOException {
        String name = buffer.getString();
        if (log.isDebugEnabled()) {
            log.debug("handleSignal({}): {}", this, name);
        }

        return handleSignalParsed(name);
    }

    protected RequestHandler.Result handleSignalParsed(String name) throws IOException {
        Signal signal = Signal.get(name);
        if (signal != null) {
            StandardEnvironment environ = getEnvironment();
            environ.signal(this, signal);
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

        return handleBreakParsed(breakLength);
    }

    protected RequestHandler.Result handleBreakParsed(long breakLength) throws IOException {
        StandardEnvironment environ = getEnvironment();
        environ.signal(this, Signal.INT);
        return RequestHandler.Result.ReplySuccess;
    }

    protected RequestHandler.Result handleShell(
            String request, Buffer buffer, boolean wantReply)
            throws IOException {
        // If we're already closing, ignore incoming data
        if (isClosing()) {
            if (log.isDebugEnabled()) {
                log.debug("handleShell({}) - closing", this);
            }
            return RequestHandler.Result.ReplyFailure;
        }

        return handleShellParsed(request);
    }

    protected RequestHandler.Result handleShellParsed(String request) throws IOException {
        ServerSession shellSession = Objects.requireNonNull(getServerSession(), "No server session");
        ServerFactoryManager manager = Objects.requireNonNull(shellSession.getFactoryManager(), "No server factory manager");
        ShellFactory factory = manager.getShellFactory();
        if (factory == null) {
            if (log.isDebugEnabled()) {
                log.debug("handleShell({}) - no shell factory", this);
            }
            return RequestHandler.Result.ReplyFailure;
        }

        try {
            commandInstance = factory.createShell(this);
        } catch (RuntimeException | IOException | Error e) {
            warn("handleShell({}) Failed ({}) to create shell: {}",
                    this, e.getClass().getSimpleName(), e.getMessage(), e);
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

    protected RequestHandler.Result handleExec(
            String request, Buffer buffer, boolean wantReply)
            throws IOException {
        // If we're already closing, ignore incoming data
        if (isClosing()) {
            return RequestHandler.Result.ReplyFailure;
        }

        String commandLine = buffer.getString();
        return handleExecParsed(request, commandLine);
    }

    protected RequestHandler.Result handleExecParsed(
            String request, String commandLine)
            throws IOException {
        ServerSession cmdSession = Objects.requireNonNull(getServerSession(), "No server session");
        ServerFactoryManager manager = Objects.requireNonNull(cmdSession.getFactoryManager(), "No server factory manager");
        CommandFactory factory = manager.getCommandFactory();
        if (factory == null) {
            log.warn("handleExec({}) No command factory for command: {}", this, commandLine);
            return RequestHandler.Result.ReplyFailure;
        }

        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("handleExec({}) Executing command: {}", this, commandLine);
        }

        try {
            commandInstance = factory.createCommand(this, commandLine);
        } catch (RuntimeException | IOException | Error e) {
            warn("handleExec({}) Failed ({}) to create command for {}: {}",
                    this, e.getClass().getSimpleName(), commandLine, e.getMessage(), e);
            return RequestHandler.Result.ReplyFailure;
        }

        if (commandInstance == null) {
            log.warn("handleExec({}) Unsupported command: {}", this, commandLine);
            return RequestHandler.Result.ReplyFailure;
        }

        return prepareChannelCommand(request, commandInstance);
    }

    protected RequestHandler.Result handleSubsystem(
            String request, Buffer buffer, boolean wantReply)
            throws IOException {
        String subsystem = buffer.getString();
        if (log.isDebugEnabled()) {
            log.debug("handleSubsystem({})[want-reply={}] subsystem={}", this, wantReply, subsystem);
        }

        return handleSubsystemParsed(request, subsystem);
    }

    protected RequestHandler.Result handleSubsystemParsed(String request, String subsystem) throws IOException {
        ServerFactoryManager manager = Objects.requireNonNull(getServerSession(), "No server session").getFactoryManager();
        Collection<SubsystemFactory> factories
                = Objects.requireNonNull(manager, "No server factory manager").getSubsystemFactories();
        if (GenericUtils.isEmpty(factories)) {
            log.warn("handleSubsystem({}) No factories for subsystem: {}", this, subsystem);
            return RequestHandler.Result.ReplyFailure;
        }

        try {
            commandInstance = SubsystemFactory.createSubsystem(this, factories, subsystem);
        } catch (IOException | RuntimeException | Error e) {
            warn("handleSubsystem({}) Failed ({}) to create command for subsystem={}: {}",
                    this, e.getClass().getSimpleName(), subsystem, e.getMessage(), e);
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

        boolean debugEnabled = log.isDebugEnabled();
        if (command != cmd) {
            if (debugEnabled) {
                log.debug("prepareChannelCommand({})[{}] replaced original command", this, request);
            }
            commandInstance = command;
        }

        if (debugEnabled) {
            log.debug("prepareChannelCommand({})[{}] prepared command", this, request);
        }
        return RequestHandler.Result.ReplySuccess;
    }

    /**
     * For {@link Command} to install {@link ChannelDataReceiver}. When you do this,
     * {@link Command#setInputStream(java.io.InputStream)} or
     * {@link org.apache.sshd.server.command.AsyncCommand#setIoInputStream(org.apache.sshd.common.io.IoInputStream)}
     * will no longer be invoked. If you call this method from {@code Command#start(ChannelSession, Environment)}, the
     * input stream you received in {@link Command#setInputStream(java.io.InputStream)} will not read any data.
     *
     * @param receiver The {@link ChannelDataReceiver} instance
     */
    public void setDataReceiver(ChannelDataReceiver receiver) {
        this.receiver = receiver;
    }

    /**
     * A special {@link ChannelDataReceiver} that can be used to receive data sent as &quot;extended&quot; - usually
     * STDERR. <B>Note:</B> by default any such data sent to the channel session causes an exception, but specific
     * implementations may choose to register such a receiver (e.g., for custom usage of the STDERR stream). A good
     * place in the code to register such a writer would be in commands that also implement {@code ChannelSessionAware}.
     *
     * @param extendedDataWriter The {@link ChannelDataReceiver}.
     */
    public void setExtendedDataWriter(ChannelDataReceiver extendedDataWriter) {
        this.extendedDataWriter = extendedDataWriter;
    }

    /**
     * Called by {@link #prepareChannelCommand(String, Command)} in order to set up the command's streams, session,
     * file-system, exit callback, etc..
     *
     * @param  requestType The request that caused the command to be created
     * @param  command     The created {@link Command} - may be {@code null}
     * @return             The updated command instance - if {@code null} then the request that initially caused the
     *                     creation of the command is failed and the original command (if any) destroyed (eventually).
     *                     <B>Note:</B> if a different command instance than the input one is returned, then it is up to
     *                     the implementor to take care of the wrapping or destruction of the original command instance.
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
            ((FileSystemAware) command).setFileSystemFactory(factory, session);
        }
        // If the shell wants to use non-blocking io
        if (command instanceof AsyncCommand) {
            asyncOut = new ChannelAsyncOutputStream(this, SshConstants.SSH_MSG_CHANNEL_DATA);
            asyncErr = new ChannelAsyncOutputStream(this, SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA);
            ((AsyncCommand) command).setIoOutputStream(asyncOut);
            ((AsyncCommand) command).setIoErrorStream(asyncErr);
        } else {
            Window wRemote = getRemoteWindow();
            out = new ChannelOutputStream(
                    this, wRemote, log, SshConstants.SSH_MSG_CHANNEL_DATA, false);
            err = new ChannelOutputStream(
                    this, wRemote, log, SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA, false);
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

        if (receiverBuffer != null) {
            Buffer buffer = receiverBuffer;
            receiverBuffer = null;
            doWriteData(buffer.array(), buffer.rpos(), buffer.available());
        }

        if (extendedDataBuffer != null) {
            if (extendedDataWriter == null) {
                throw new UnsupportedOperationException(
                        "No extended data writer available though " + extendedDataBuffer.available() + " bytes accumulated");
            }

            Buffer buffer = extendedDataBuffer;
            extendedDataBuffer = null;
            doWriteExtendedData(buffer.array(), buffer.rpos(), buffer.available());
        }

        command.setExitCallback((exitValue, exitMessage) -> {
            try {
                closeShell(exitValue);
                if (log.isDebugEnabled()) {
                    log.debug("onExit({}) code={} message='{}' shell closed",
                            ChannelSession.this, exitValue, exitMessage);
                }
            } catch (IOException e) {
                log.warn("onExit({}) code={} message='{}' {} closing shell: {}",
                        ChannelSession.this, exitValue, exitMessage, e.getClass().getSimpleName(), e.getMessage());
            }
        });

        return command;
    }

    protected int getPtyModeValue(PtyMode mode) {
        Number v = getEnvironment().getPtyModes().get(mode);
        return v != null ? v.intValue() : 0;
    }

    protected RequestHandler.Result handleAgentForwarding(
            String requestType, Buffer buffer, boolean wantReply)
            throws IOException {
        return handleAgentForwardingParsed(requestType);
    }

    protected RequestHandler.Result handleAgentForwardingParsed(String requestType) throws IOException {
        ServerSession session = getServerSession();
        PropertyResolverUtils.updateProperty(session, CoreModuleProperties.AGENT_FORWARDING_TYPE, requestType);

        FactoryManager manager = Objects.requireNonNull(session.getFactoryManager(), "No session factory manager");
        AgentForwardingFilter filter = manager.getAgentForwardingFilter();
        SshAgentFactory factory = manager.getAgentFactory();
        boolean debugEnabled = log.isDebugEnabled();
        try {
            if ((factory == null) || (filter == null) || (!filter.canForwardAgent(session, requestType))) {
                if (debugEnabled) {
                    log.debug("handleAgentForwarding({})[haveFactory={},haveFilter={}] filtered out request={}",
                            this, factory != null, filter != null, requestType);
                }
                return RequestHandler.Result.ReplyFailure;
            }
        } catch (Error e) {
            warn("handleAgentForwarding({}) failed ({}) to consult forwarding filter for '{}': {}",
                    this, e.getClass().getSimpleName(), requestType, e.getMessage(), e);
            throw new RuntimeSshException(e);
        }

        AgentForwardSupport agentForward = service.getAgentForwardSupport();
        if (agentForward == null) {
            if (debugEnabled) {
                log.debug("handleAgentForwarding({}) no agent forward support", this);
            }
            return RequestHandler.Result.ReplyFailure;
        }

        String authSocket = agentForward.initialize();
        addEnvVariable(SshAgent.SSH_AUTHSOCKET_ENV_NAME, authSocket);
        return RequestHandler.Result.ReplySuccess;
    }

    protected RequestHandler.Result handleX11Forwarding(
            String requestType, Buffer buffer, boolean wantReply)
            throws IOException {
        ServerSession session = getServerSession();
        boolean singleConnection = buffer.getBoolean();
        String authProtocol = buffer.getString();
        String authCookie = buffer.getString();
        int screenId = buffer.getInt();

        return handleX11ForwardingParsed(requestType, session, singleConnection, authProtocol, authCookie, screenId);
    }

    protected RequestHandler.Result handleX11ForwardingParsed(
            String requestType, ServerSession session, boolean singleConnection,
            String authProtocol, String authCookie, int screenId)
            throws IOException {
        FactoryManager manager = Objects.requireNonNull(session.getFactoryManager(), "No factory manager");
        X11ForwardingFilter filter = manager.getX11ForwardingFilter();
        boolean debugEnabled = log.isDebugEnabled();
        try {
            if ((filter == null) || (!filter.canForwardX11(session, requestType))) {
                if (debugEnabled) {
                    log.debug(
                            "handleX11Forwarding({}) single={}, protocol={}, cookie={}, screen={}, filter={}: filtered request={}",
                            this, singleConnection, authProtocol, authCookie, screenId, filter, requestType);
                }
                return RequestHandler.Result.ReplyFailure;
            }
        } catch (Error e) {
            warn("handleX11Forwarding({}) failed ({}) to consult forwarding filter for '{}': {}",
                    this, e.getClass().getSimpleName(), requestType, e.getMessage(), e);
            throw new RuntimeSshException(e);
        }

        X11ForwardSupport x11Forward = service.getX11ForwardSupport();
        if (x11Forward == null) {
            if (debugEnabled) {
                log.debug("handleX11Forwarding({}) single={}, protocol={}, cookie={}, screen={} - no forwarder'",
                        this, singleConnection, authProtocol, authCookie, screenId);
            }
            return RequestHandler.Result.ReplyFailure;
        }

        String display = x11Forward.createDisplay(singleConnection, authProtocol, authCookie, screenId);
        if (debugEnabled) {
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
        StandardEnvironment e = getEnvironment();
        e.set(name, value);
    }

    public StandardEnvironment getEnvironment() {
        return env;
    }

    protected void closeShell(int exitValue) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("closeShell({}) exit code={}", this, exitValue);
        }

        if (!isClosing()) {
            if (out != null) {
                out.flush();
            }
            sendEof();
            sendExitStatus(exitValue);
            commandExitFuture.setClosed();
            close(false);
        } else {
            commandExitFuture.setClosed();
        }
    }
}
