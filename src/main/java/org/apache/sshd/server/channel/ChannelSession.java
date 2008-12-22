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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.channel.ChannelPipedOutputStream;
import org.apache.sshd.common.channel.ChannelPipedInputStream;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.LfToCrLfFilterOutputStream;
import org.apache.sshd.common.util.LoggingFilterOutputStream;
import org.apache.sshd.common.util.IoUtils;
import org.apache.sshd.server.ServerChannel;
import org.apache.sshd.server.ShellFactory;
import org.apache.sshd.server.CommandFactory;
import org.apache.sshd.server.session.ServerSession;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public class ChannelSession extends AbstractServerChannel {

    public static class Factory implements NamedFactory<ServerChannel> {

        public String getName() {
            return "session";
        }

        public ServerChannel create() {
            return new ChannelSession();
        }
    }

    protected static enum PtyMode {
        // Chars
        VINTR(1), VQUIT(2), VERASE(3), VKILL(4), VEOF(5), VEOL(6), VEOL2(7), VSTART(8), VSTOP(9),
        VSUSP(10), VDSUSP(11), VREPRINT(12), VWERASE(13), VLNEXT(14), VFLUSH(15), VSWTCH(16), VSTATUS(17), VDISCARD(18),
        // I flags
        IGNPAR(30), PARMRK(31), INPCK(32), ISTRIP(33), INCLR(34), IGNCR(35), ICRNL(36), IUCLC(37), IXON(38), IXANY(39),
        IXOFF(40), IMAXBEL(41),
        // L flags
        ISIG(50), ICANON(51), XCASE(52), ECHO(53), ECHOE(54), ECHOK(55), ECHONL(56), NOFLSH(57), TOSTOP(58), IEXTEN(59),
        ECHOCTL(60), ECHOKE(61), PENDIN(62),
        // O flags
        OPOST(70), OLCUC(71), ONLCR(72), OCRNL(73), ONOCR(74), ONLRET(75),
        // C flags
        CS7(90), CS8(91), PARENB(92), PARODD(93),
        // Speeed
        TTY_OP_ISPEED(128), TTY_OP_OSPEED(129);

        private int v;
        private PtyMode(int v) {
            this.v = v;
        }

        public int toInt() {
            return v;
        }

        static Map<Integer,PtyMode> commands;
        static {
            commands = new HashMap<Integer, PtyMode>();
            for (PtyMode c : PtyMode.values()) {
                commands.put(c.toInt(), c);
            }
        }
        public static PtyMode fromInt(int b) {
            return commands.get(b);
        }
    }

    protected static class PtyModeValue {
        public final PtyMode mode;
        public final int value;

        public PtyModeValue(PtyMode mode, int value) {
            this.mode = mode;
            this.value = value;
        }

        public String toString() {
            return mode + "(" + mode.toInt() + ") =" + value;
        }
    }

    protected String type;
    protected PtyModeValue[] ptyModes;
    protected InputStream in;
    protected OutputStream out;
    protected OutputStream err;
    protected ShellFactory.Shell shell;
    protected OutputStream shellIn;
    protected InputStream shellOut;
    protected InputStream shellErr;
    protected Map<String,String> env;

    public ChannelSession() {
    }

    public CloseFuture close(boolean immediately) {
        return super.close(immediately).addListener(new SshFutureListener() {
            public void operationComplete(SshFuture sshFuture) {
                if (shell != null) {
                    shell.destroy();
                    shell = null;
                }
                IoUtils.closeQuietly(in, out, err, shellIn, shellOut, shellErr);
            }
        });
    }

    public void handleRequest(Buffer buffer) throws IOException {
        log.info("Received SSH_MSG_CHANNEL_REQUEST on channel {}", id);
        String type = buffer.getString();
        log.info("Received channel request: {}", type);
        if (!handleRequest(type, buffer)) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_FAILURE);
            buffer.putInt(id);
            session.writePacket(buffer);
        }
    }

    protected void doWriteData(byte[] data, int off, int len) throws IOException {
        shellIn.write(data, off, len);
        shellIn.flush();
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
            if (checkType(type)) {
                return handleShell(buffer);
            } else {
                return false;
            }
        }
        if ("exec".equals(type)) {
            if (checkType(type)) {
                return handleExec(buffer);
            } else {
                return false;
            }
        }
        if ("subsystem".equals(type)) {
            if (checkType(type)) {
                return handleSubsystem(buffer);
            } else {
                return false;
            }
        }
        return false;
    }

    /**
     * Only one of "shell", "exec" or "subsystem" command
     * is permitted for a given channel.
     *
     * @param type
     * @return
     */
    private boolean checkType(String type) {
        if (this.type == null) {
            this.type = type;
            return true;
        } else {
            return false;
        }
    }

    protected boolean handleEnv(Buffer buffer) throws IOException {
        boolean wantReply = buffer.getBoolean();
        String name = buffer.getString();
        String value = buffer.getString();
        addEnvVariable(name, value);
        log.debug("env for channel {}: {} = {}", new Object[] { id, name, value });
        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_SUCCESS);
            buffer.putInt(id);
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
        List<PtyModeValue> modeList = new ArrayList<PtyModeValue>();
        for (int i = 0; i < modes.length && modes[i] != 0;) {
            PtyMode mode = PtyMode.fromInt(modes[i++]);
            int val  = ((modes[i++] << 24) & 0xff000000) |
                       ((modes[i++] << 16) & 0x00ff0000) |
                       ((modes[i++] <<  8) & 0x0000ff00) |
                       ((modes[i++]      ) & 0x000000ff);
            PtyModeValue m = new PtyModeValue(mode, val);
            modeList.add(m);
        }
        ptyModes = modeList.toArray(new PtyModeValue[0]);
        if (log.isDebugEnabled()) {
            StringBuffer strModes = new StringBuffer();
            for (PtyModeValue m : ptyModes) {
                if (strModes.length() > 0) {
                    strModes.append(", ");
                }
                strModes.append(m);
            }
            log.debug("pty for channel {}: term={}, size=({} - {}), pixels=({}, {}), modes=[{}]", new Object[] { id, term, tColumns, tRows, tWidth, tHeight, strModes.toString() });
        }
        addEnvVariable("TERM", term);
        // TODO: handle pty request correctly
        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_SUCCESS);
            buffer.putInt(id);
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
        // TODO: handle window-change request correctly
        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_SUCCESS);
            buffer.putInt(id);
            session.writePacket(buffer);
        }
        return true;
    }

    protected boolean handleSignal(Buffer buffer) throws IOException {
        boolean wantReply = buffer.getBoolean();
        String name = buffer.getString();
        log.debug("Signal received on channel {}: {}", id, name);
        // TODO: handle signal request correctly
        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_SUCCESS);
            buffer.putInt(id);
            session.writePacket(buffer);
        }
        return true;
    }

    protected boolean handleShell(Buffer buffer) throws IOException {
        boolean wantReply = buffer.getBoolean();

        if (((ServerSession) session).getServerFactoryManager().getShellFactory() == null) {
            return false;
        }
        addEnvVariable("USER", ((ServerSession) session).getUsername());
        shell = ((ServerSession) session).getServerFactoryManager().getShellFactory().createShell();
        out = new ChannelOutputStream(this, remoteWindow, log, SshConstants.Message.SSH_MSG_CHANNEL_DATA);
        err = new ChannelOutputStream(this, remoteWindow, log, SshConstants.Message.SSH_MSG_CHANNEL_EXTENDED_DATA);
        // Wrap in logging filters
        out = new LoggingFilterOutputStream(out, "OUT:", log);
        err = new LoggingFilterOutputStream(err, "ERR:", log);
        if (getPtyModeValue(PtyMode.ONLCR) != 0) {
            out = new LfToCrLfFilterOutputStream(out);
            err = new LfToCrLfFilterOutputStream(err);
        }
        in = new ChannelPipedInputStream(localWindow);
        shellIn = new ChannelPipedOutputStream((ChannelPipedInputStream) in);
        shell.setInputStream(in);
        shell.setOutputStream(out);
        shell.setErrorStream(err);
        shell.setExitCallback(new ShellFactory.ExitCallback() {
            public void onExit(int exitValue) {
                try {
                    closeShell(exitValue);
                } catch (IOException e) {
                    log.info("Error closing shell", e);
                }
            }
        });
        shell.start(env);
        shellIn = new LoggingFilterOutputStream(shellIn, "IN: ", log);

        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_SUCCESS);
            buffer.putInt(id);
            session.writePacket(buffer);
        }
        return true;
    }

    protected int getPtyModeValue(PtyMode mode) {
        if (ptyModes != null) {
            for (PtyModeValue m : ptyModes) {
                if (m.mode == mode) {
                    return m.value;
                }
            }
        }
        return 0;
    }

    protected boolean handleExec(Buffer buffer) throws IOException {
        boolean wantReply = buffer.getBoolean();
        String commandLine = buffer.getString();

        if (((ServerSession) session).getServerFactoryManager().getCommandFactory() == null) {
            return false;
        }

        CommandFactory.Command command = ((ServerSession) session).getServerFactoryManager().getCommandFactory().createCommand(commandLine);
        // If the command wants to be aware of the session, let's do that
        if (command instanceof CommandFactory.SessionAware) {
            ((CommandFactory.SessionAware) command).setSession((ServerSession) session);
        }
        // Set streams and exit callback
        out = new ChannelOutputStream(this, remoteWindow, log, SshConstants.Message.SSH_MSG_CHANNEL_DATA);
        err = new ChannelOutputStream(this, remoteWindow, log, SshConstants.Message.SSH_MSG_CHANNEL_EXTENDED_DATA);
        // Wrap in logging filters
        out = new LoggingFilterOutputStream(out, "OUT:", log);
        err = new LoggingFilterOutputStream(err, "ERR:", log);
        in = new ChannelPipedInputStream(localWindow);
        shellIn = new ChannelPipedOutputStream((ChannelPipedInputStream) in);
        command.setInputStream(in);
        command.setOutputStream(out);
        command.setErrorStream(err);
        command.setExitCallback(new CommandFactory.ExitCallback() {
            public void onExit(int exitValue) {
                try {
                    closeShell(exitValue);
                } catch (IOException e) {
                    log.info("Error closing shell", e);
                }
            }
        });
        // Launch command
        command.start();

        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_SUCCESS);
            buffer.putInt(id);
            session.writePacket(buffer);
        }

        return true;
    }

    protected boolean handleSubsystem(Buffer buffer) throws IOException {
        boolean wantReply = buffer.getBoolean();
        // TODO: start subsystem
        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_SUCCESS);
            buffer.putInt(id);
            session.writePacket(buffer);
        }
        return true;
    }

    protected synchronized void addEnvVariable(String name, String value) {
        if (env == null) {
            env = new HashMap<String,String>();
        }
        env.put(name, value);
    }

    protected void closeShell(int exitValue) throws IOException {
        sendEof();
        sendExitStatus(exitValue);
        // TODO: We should wait for all streams to be consumed before closing the channel
        close(false);
    }

}