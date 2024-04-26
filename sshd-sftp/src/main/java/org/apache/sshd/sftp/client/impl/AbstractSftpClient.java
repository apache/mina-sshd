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
package org.apache.sshd.sftp.client.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.subsystem.AbstractSubsystemClient;
import org.apache.sshd.common.Property;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.sftp.SftpModuleProperties;
import org.apache.sshd.sftp.client.FullAccessSftpClient;
import org.apache.sshd.sftp.client.SftpErrorDataHandler;
import org.apache.sshd.sftp.client.extensions.BuiltinSftpClientExtensions;
import org.apache.sshd.sftp.client.extensions.SftpClientExtension;
import org.apache.sshd.sftp.client.extensions.SftpClientExtensionFactory;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpException;
import org.apache.sshd.sftp.common.SftpHelper;
import org.apache.sshd.sftp.common.extensions.ParserUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSftpClient
        extends AbstractSubsystemClient
        implements FullAccessSftpClient, SftpErrorDataHandler {
    public static final int INIT_COMMAND_SIZE = Byte.BYTES /* command */ + Integer.BYTES /* version */;
    /**
     * Property that can be used on the {@link org.apache.sshd.common.FactoryManager} to control the internal timeout
     * used by the client to complete the buffer sending in {@link #send(int, Buffer)}.
     */
    public static final Property<Duration> SFTP_CLIENT_CMD_TIMEOUT
            = Property.duration("sftp-client-cmd-timeout", Duration.ofSeconds(30L));

    protected final SftpErrorDataHandler errorDataHandler;

    private final Attributes fileOpenAttributes = new Attributes();
    private final AtomicReference<Map<String, Object>> parsedExtensionsHolder = new AtomicReference<>(null);

    protected AbstractSftpClient(SftpErrorDataHandler delegateHandler) {
        errorDataHandler = (delegateHandler == null) ? SftpErrorDataHandler.EMPTY : delegateHandler;
        fileOpenAttributes.setType(SftpConstants.SSH_FILEXFER_TYPE_REGULAR);
    }

    @Override
    public Channel getChannel() {
        return getClientChannel();
    }

    @Override
    public <E extends SftpClientExtension> E getExtension(Class<? extends E> extensionType) {
        Object instance = getExtension(BuiltinSftpClientExtensions.fromType(extensionType));
        if (instance == null) {
            return null;
        } else {
            return extensionType.cast(instance);
        }
    }

    @Override
    public SftpClientExtension getExtension(SftpClientExtensionFactory factory) {
        if (factory == null) {
            return null;
        }

        Map<String, byte[]> extensions = getServerExtensions();
        Map<String, Object> parsed = getParsedServerExtensions(extensions);
        return factory.create(this, this, extensions, parsed);
    }

    protected Map<String, Object> getParsedServerExtensions() {
        return getParsedServerExtensions(getServerExtensions());
    }

    protected Map<String, Object> getParsedServerExtensions(Map<String, byte[]> extensions) {
        Map<String, Object> parsed = parsedExtensionsHolder.get();
        if (parsed == null) {
            parsed = ParserUtils.parse(extensions);
            if (parsed == null) {
                parsed = Collections.emptyMap();
            }
            parsedExtensionsHolder.set(parsed);
        }

        return parsed;
    }

    /**
     * @param  cmd       The command that was sent whose response contains the name to be decoded
     * @param  buf       The {@link Buffer} containing the encoded name
     * @param  nameIndex The zero-based order of the requested names for the command - e.g.,
     *                   <UL>
     *                   <LI>When listing a directory's contents each successive name will have an increasing index.
     *                   </LI>
     *
     *                   <LI>For SFTP version 3, when retrieving a single name, short name will have index=0 and the
     *                   long one index=1.</LI>
     *                   </UL>
     * @return           The decoded referenced name
     */
    protected String getReferencedName(int cmd, Buffer buf, int nameIndex) {
        Charset cs = getNameDecodingCharset();
        return buf.getString(cs);
    }

    /**
     * @param  <B>       Type of {@link Buffer} being updated
     * @param  cmd       The command for which this name is being added
     * @param  buf       The buffer instance to update
     * @param  name      The name to place in the buffer
     * @param  nameIndex The zero-based order of the name for the specific command if more than one name required -
     *                   e.g., rename, link/symbolic link
     * @return           The updated buffer
     */
    protected <B extends Buffer> B putReferencedName(int cmd, B buf, String name, int nameIndex) {
        Charset cs = getNameDecodingCharset();
        buf.putString(name, cs);
        return buf;
    }

    /**
     * Perform an SFTP request and wait until the response has been received.
     *
     * @param  cmd         the SFTP command code
     * @param  request     a {@link Buffer} containing the request data
     * @return             the {@link SftpResponse} for the request
     * @throws IOException if an error occurs
     */
    protected SftpResponse rpc(int cmd, Buffer request) throws IOException {
        int reqId = send(cmd, request);
        return response(cmd, reqId);
    }

    /**
     * Receives a response buffer, validates and returns it as a {@link SftpResponse}.
     *
     * @param  cmd         the command of the request the response is for
     * @param  requestId   the id of the request
     * @return             the {@link SftpResponse}
     * @throws IOException if the received buffer is malformed
     */
    protected SftpResponse response(int cmd, int requestId) throws IOException {
        SftpResponse result = SftpResponse.parse(cmd, receive(requestId));
        if (log.isDebugEnabled()) {
            switch (result.getType()) {
                case SftpConstants.SSH_FXP_STATUS:
                    Buffer buffer = result.getBuffer();
                    if (buffer.available() >= 4) {
                        int rpos = buffer.rpos();
                        int status = buffer.getInt();
                        buffer.rpos(rpos);
                        if (status == SftpConstants.SSH_FX_OK && cmd == SftpConstants.SSH_FXP_WRITE) {
                            // Only trace logging for data write if the status is OK
                            if (log.isTraceEnabled()) {
                                log.trace("response({}): received {}({}) for command {} (id={})", getClientChannel(),
                                        SftpConstants.getCommandMessageName(result.getType()),
                                        SftpConstants.getStatusName(status), SftpConstants.getCommandMessageName(cmd),
                                        result.getId());
                            }
                        } else {
                            log.debug("response({}): received {}({}) for command {} (id={})", getClientChannel(),
                                    SftpConstants.getCommandMessageName(result.getType()), SftpConstants.getStatusName(status),
                                    SftpConstants.getCommandMessageName(cmd), result.getId());
                        }
                    }
                    break;
                case SftpConstants.SSH_FXP_DATA:
                    if (log.isTraceEnabled()) {
                        log.debug("response({}): received {} for command {} (id={})", getClientChannel(),
                                SftpConstants.getCommandMessageName(result.getType()), SftpConstants.getCommandMessageName(cmd),
                                result.getId());
                    }
                    break;
                default:
                    log.debug("response({}): received {} for command {} (id={})", getClientChannel(),
                            SftpConstants.getCommandMessageName(result.getType()), SftpConstants.getCommandMessageName(cmd),
                            result.getId());
                    break;
            }
        }
        return result;
    }

    /**
     * Sends the specified command, waits for the response and then invokes {@link #checkResponseStatus(SftpResponse)}
     *
     * @param  cmd         The command to send
     * @param  request     The request {@link Buffer}
     * @throws IOException If failed to send, receive or check the returned status
     * @see                #send(int, Buffer)
     * @see                #receive(int)
     * @see                #checkResponseStatus(SftpResponse)
     */
    protected void checkCommandStatus(int cmd, Buffer request) throws IOException {
        checkResponseStatus(rpc(cmd, request));
    }

    /**
     * Checks if the incoming response is an {@code SSH_FXP_STATUS} one, and if so whether the substatus is
     * {@code SSH_FX_OK}.
     *
     * @param  response    The received {@link SftpResponse}
     * @throws IOException If response does not carry a status or carries a bad status code
     * @see                #checkResponseStatus(int, int, SftpStatus)
     */
    protected void checkResponseStatus(SftpResponse response) throws IOException {
        if (response.getType() == SftpConstants.SSH_FXP_STATUS) {
            checkResponseStatus(response.getCmd(), response.getId(), SftpStatus.parse(response));
        } else {
            IOException err = handleUnexpectedPacket(SftpConstants.SSH_FXP_STATUS, response);
            if (err != null) {
                throw err;
            }
        }
    }

    /**
     * @param  cmd         The sent command opcode
     * @param  id          The request id
     * @param  status      The {@link SftpStatus}
     * @throws IOException if {@code !status.isOk()}
     * @see                #throwStatusException(int, int, SftpStatus)
     */
    protected void checkResponseStatus(int cmd, int id, SftpStatus status) throws IOException {
        if (!status.isOk()) {
            throwStatusException(cmd, id, status);
        } else if (log.isTraceEnabled()) {
            log.trace("throwStatusException({})[id={}] cmd={} status={}",
                    getClientChannel(), id, SftpConstants.getCommandMessageName(cmd),
                    status);
        }
    }

    protected void throwStatusException(int cmd, int id, SftpStatus status) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("throwStatusException({})[id={}] cmd={} status={}", getClientChannel(), id,
                    SftpConstants.getCommandMessageName(cmd), status);
        }
        throw new SftpException(status.getStatusCode(), status.getMessage());
    }

    /**
     * @param  cmd         Command to be sent
     * @param  request     The {@link Buffer} containing the request
     * @return             The received handle identifier
     * @throws IOException If failed to send/receive or process the response
     * @see                #send(int, Buffer)
     * @see                #receive(int)
     * @see                #checkHandleResponse(SftpResponse)
     */
    protected byte[] checkHandle(int cmd, Buffer request) throws IOException {
        return checkHandleResponse(rpc(cmd, request));
    }

    protected byte[] checkHandleResponse(SftpResponse response) throws IOException {
        switch (response.getType()) {
            case SftpConstants.SSH_FXP_HANDLE:
                return ValidateUtils.checkNotNullAndNotEmpty(response.getBuffer().getBytes(), "Null/empty handle in buffer",
                        GenericUtils.EMPTY_OBJECT_ARRAY);
            case SftpConstants.SSH_FXP_STATUS:
                throwStatusException(response.getCmd(), response.getId(), SftpStatus.parse(response));
                return null;
            default:
                return handleUnexpectedHandlePacket(response);
        }
    }

    protected byte[] handleUnexpectedHandlePacket(SftpResponse response) throws IOException {
        IOException err = handleUnexpectedPacket(SftpConstants.SSH_FXP_HANDLE, response);
        if (err != null) {
            throw err;
        }
        throw new SshException("No handling for unexpected handle packet id=" + response.getId() + ", type="
                               + SftpConstants.getCommandMessageName(response.getType()) + ", length=" + response.getLength());
    }

    /**
     * @param  cmd         Command to be sent
     * @param  request     Request {@link Buffer}
     * @return             The decoded response {@code Attributes}
     * @throws IOException If failed to send/receive or process the response
     * @see                #send(int, Buffer)
     * @see                #receive(int)
     * @see                #checkAttributesResponse(SftpResponse)
     */
    protected Attributes checkAttributes(int cmd, Buffer request) throws IOException {
        return checkAttributesResponse(rpc(cmd, request));
    }

    protected Attributes checkAttributesResponse(SftpResponse response) throws IOException {
        switch (response.getType()) {
            case SftpConstants.SSH_FXP_ATTRS:
                return readAttributes(response.getCmd(), response.getBuffer(), new AtomicInteger(0));
            case SftpConstants.SSH_FXP_STATUS:
                throwStatusException(response.getCmd(), response.getId(), SftpStatus.parse(response));
                return null;
            default:
                return handleUnexpectedAttributesPacket(response);
        }
    }

    protected Attributes handleUnexpectedAttributesPacket(SftpResponse response)
            throws IOException {
        IOException err = handleUnexpectedPacket(SftpConstants.SSH_FXP_ATTRS, response);
        if (err != null) {
            throw err;
        }
        return null;
    }

    /**
     * @param  cmd         Command to be sent
     * @param  request     The request {@link Buffer}
     * @return             The retrieved name
     * @throws IOException If failed to send/receive or process the response
     * @see                #send(int, Buffer)
     * @see                #receive(int)
     * @see                #checkOneNameResponse(SftpResponse)
     */
    protected String checkOneName(int cmd, Buffer request) throws IOException {
        return checkOneNameResponse(rpc(cmd, request));
    }

    protected String checkOneNameResponse(SftpResponse response) throws IOException {
        switch (response.getType()) {
            case SftpConstants.SSH_FXP_NAME:
                Buffer buffer = response.getBuffer();
                int cmd = response.getCmd();
                int len = buffer.getInt();
                if (len != 1) {
                    throw new SshException("SFTP error: received " + len + " names instead of 1");
                }

                AtomicInteger nameIndex = new AtomicInteger(0);
                String name = getReferencedName(cmd, buffer, nameIndex.getAndIncrement());

                String longName = null;
                int version = getVersion();
                if (version == SftpConstants.SFTP_V3) {
                    longName = getReferencedName(cmd, buffer, nameIndex.getAndIncrement());
                }

                Attributes attrs = SftpHelper.complete(readAttributes(cmd, buffer, nameIndex), longName);
                Boolean indicator = SftpHelper.getEndOfListIndicatorValue(buffer, version);
                // TODO decide what to do if not-null and not TRUE
                if (log.isTraceEnabled()) {
                    log.trace("checkOneNameResponse({})[id={}] {} ({})[{}] eol={}: {}", getClientChannel(), response.getId(),
                            SftpConstants.getCommandMessageName(cmd), name, longName, indicator, attrs);
                }
                return name;
            case SftpConstants.SSH_FXP_STATUS:
                throwStatusException(response.getCmd(), response.getId(), SftpStatus.parse(response));
                return null;
            default:
                return handleUnknownOneNamePacket(response);
        }
    }

    protected String handleUnknownOneNamePacket(SftpResponse response) throws IOException {
        IOException err = handleUnexpectedPacket(SftpConstants.SSH_FXP_NAME, response);
        if (err != null) {
            throw err;
        }

        return null;
    }

    protected Attributes readAttributes(int cmd, Buffer buffer, AtomicInteger nameIndex) throws IOException {
        Attributes attrs = new Attributes();
        int flags = buffer.getInt();
        int version = getVersion();
        if (version == SftpConstants.SFTP_V3) {
            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_SIZE) != 0) {
                attrs.setSize(buffer.getLong());
            }
            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_UIDGID) != 0) {
                attrs.owner(buffer.getInt(), buffer.getInt());
            }
            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
                int perms = buffer.getInt();
                attrs.setPermissions(perms);
                attrs.setType(SftpHelper.permissionsToFileType(perms));
            }

            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME) != 0) {
                attrs.setAccessTime(SftpHelper.readTime(buffer, version, flags));
                attrs.setModifyTime(SftpHelper.readTime(buffer, version, flags));
            }
        } else if (version >= SftpConstants.SFTP_V4) {
            attrs.setType(buffer.getUByte());
            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_SIZE) != 0) {
                attrs.setSize(buffer.getLong());
            }

            if ((version >= SftpConstants.SFTP_V6) && ((flags & SftpConstants.SSH_FILEXFER_ATTR_ALLOCATION_SIZE) != 0)) {
                @SuppressWarnings("unused")
                long allocSize = buffer.getLong(); // TODO handle allocation size
            }

            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_OWNERGROUP) != 0) {
                attrs.setOwner(buffer.getString());
                attrs.setGroup(buffer.getString());
            }
            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
                attrs.setPermissions(buffer.getInt());
            }

            // update the permissions according to the type
            int perms = attrs.getPermissions();
            perms |= SftpHelper.fileTypeToPermission(attrs.getType());
            attrs.setPermissions(perms);

            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_ACCESSTIME) != 0) {
                attrs.setAccessTime(SftpHelper.readTime(buffer, version, flags));
            }
            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_CREATETIME) != 0) {
                attrs.setCreateTime(SftpHelper.readTime(buffer, version, flags));
            }
            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_MODIFYTIME) != 0) {
                attrs.setModifyTime(SftpHelper.readTime(buffer, version, flags));
            }
            if ((version >= SftpConstants.SFTP_V6) && (flags & SftpConstants.SSH_FILEXFER_ATTR_CTIME) != 0) {
                @SuppressWarnings("unused")
                FileTime attrsChangedTime = SftpHelper.readTime(buffer, version, flags); // TODO the last time the file
                                                                                        // attributes were changed
            }

            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_ACL) != 0) {
                attrs.setAcl(SftpHelper.readACLs(buffer, version));
            }

            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_BITS) != 0) {
                @SuppressWarnings("unused")
                int bits = buffer.getInt();
                @SuppressWarnings("unused")
                int valid = 0xffffffff;
                if (version >= SftpConstants.SFTP_V6) {
                    valid = buffer.getInt();
                }
                // TODO: handle attrib bits
            }

            if (version >= SftpConstants.SFTP_V6) {
                if ((flags & SftpConstants.SSH_FILEXFER_ATTR_TEXT_HINT) != 0) {
                    @SuppressWarnings("unused")
                    boolean text = buffer.getBoolean(); // TODO: handle text
                }
                if ((flags & SftpConstants.SSH_FILEXFER_ATTR_MIME_TYPE) != 0) {
                    @SuppressWarnings("unused")
                    String mimeType = buffer.getString(); // TODO: handle mime-type
                }
                if ((flags & SftpConstants.SSH_FILEXFER_ATTR_LINK_COUNT) != 0) {
                    @SuppressWarnings("unused")
                    int nlink = buffer.getInt(); // TODO: handle link-count
                }
                if ((flags & SftpConstants.SSH_FILEXFER_ATTR_UNTRANSLATED_NAME) != 0) {
                    @SuppressWarnings("unused")
                    String untranslated = getReferencedName(cmd, buffer, nameIndex.getAndIncrement());
                    // TODO: handle untranslated name
                }
            }
        } else {
            throw new IllegalStateException("readAttributes - unsupported version: " + version);
        }

        if ((flags & SftpConstants.SSH_FILEXFER_ATTR_EXTENDED) != 0) {
            attrs.setExtensions(SftpHelper.readExtensions(buffer));
        }

        return attrs;
    }

    protected <B extends Buffer> B writeAttributes(int cmd, B buffer, Attributes attributes) {
        return SftpHelper.writeAttributes(buffer, attributes, getVersion());
    }

    @Override
    public CloseableHandle open(String path, Collection<OpenMode> options) throws IOException {
        if (!isOpen()) {
            throw new IOException("open(" + path + ")[" + options + "] client is closed");
        }

        /*
         * Be consistent with FileChannel#open - if no mode specified then READ is assumed
         */
        if (GenericUtils.isEmpty(options)) {
            options = EnumSet.of(OpenMode.Read);
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE /* some extra fields */, false);
        buffer = putReferencedName(SftpConstants.SSH_FXP_OPEN, buffer, path, 0);

        int version = getVersion();
        int mode = 0;
        if (version < SftpConstants.SFTP_V5) {
            for (OpenMode m : options) {
                switch (m) {
                    case Read:
                        mode |= SftpConstants.SSH_FXF_READ;
                        break;
                    case Write:
                        mode |= SftpConstants.SSH_FXF_WRITE;
                        break;
                    case Append:
                        mode |= SftpConstants.SSH_FXF_APPEND;
                        break;
                    case Create:
                        mode |= SftpConstants.SSH_FXF_CREAT;
                        break;
                    case Truncate:
                        mode |= SftpConstants.SSH_FXF_TRUNC;
                        break;
                    case Exclusive:
                        mode |= SftpConstants.SSH_FXF_EXCL;
                        break;
                    default: // do nothing
                }
            }
        } else {
            int access = 0;
            if (options.contains(OpenMode.Read)) {
                access |= SftpConstants.ACE4_READ_DATA | SftpConstants.ACE4_READ_ATTRIBUTES;
            }
            if (options.contains(OpenMode.Write)) {
                access |= SftpConstants.ACE4_WRITE_DATA | SftpConstants.ACE4_WRITE_ATTRIBUTES;
            }
            if (options.contains(OpenMode.Append)) {
                access |= SftpConstants.ACE4_APPEND_DATA;
                mode |= SftpConstants.SSH_FXF_APPEND_DATA;
            }
            buffer.putInt(access);

            if (options.contains(OpenMode.Create) && options.contains(OpenMode.Exclusive)) {
                mode |= SftpConstants.SSH_FXF_CREATE_NEW;
            } else if (options.contains(OpenMode.Create) && options.contains(OpenMode.Truncate)) {
                mode |= SftpConstants.SSH_FXF_CREATE_TRUNCATE;
            } else if (options.contains(OpenMode.Create)) {
                mode |= SftpConstants.SSH_FXF_OPEN_OR_CREATE;
            } else if (options.contains(OpenMode.Truncate)) {
                mode |= SftpConstants.SSH_FXF_TRUNCATE_EXISTING;
            } else {
                mode |= SftpConstants.SSH_FXF_OPEN_EXISTING;
            }
        }
        buffer.putInt(mode);
        buffer = writeAttributes(SftpConstants.SSH_FXP_OPEN, buffer, fileOpenAttributes);

        if (log.isDebugEnabled()) {
            log.debug("open({}): send SSH_FXP_OPEN {} mode={}", getClientChannel(), path, String.format("0x%04x", mode));
        }
        CloseableHandle handle = new DefaultCloseableHandle(this, path, checkHandle(SftpConstants.SSH_FXP_OPEN, buffer));
        if (log.isTraceEnabled()) {
            log.trace("open({})[{}] options={}: {}", getClientChannel(), path, options, handle);
        }
        return handle;
    }

    @Override
    public void close(Handle handle) throws IOException {
        if (!isOpen()) {
            throw new IOException("close(" + handle + ") client is closed");
        }

        if (log.isTraceEnabled()) {
            log.trace("close({}) {}", getClientChannel(), handle);
        }

        byte[] id = Objects.requireNonNull(handle, "No handle").getIdentifier();
        Buffer buffer = new ByteArrayBuffer(id.length + Long.SIZE /* some extra fields */, false);
        buffer.putBytes(id);
        if (log.isDebugEnabled()) {
            log.debug("open({})[{}]: send SSH_FXP_CLOSE", getClientChannel(), handle);
        }
        checkCommandStatus(SftpConstants.SSH_FXP_CLOSE, buffer);
    }

    @Override
    public void remove(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("remove(" + path + ") client is closed");
        }

        if (log.isDebugEnabled()) {
            log.debug("remove({}) {}", getClientChannel(), path);
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE /* some extra fields */, false);
        buffer = putReferencedName(SftpConstants.SSH_FXP_REMOVE, buffer, path, 0);
        checkCommandStatus(SftpConstants.SSH_FXP_REMOVE, buffer);
    }

    @Override
    public void rename(String oldPath, String newPath, Collection<CopyMode> options) throws IOException {
        if (!isOpen()) {
            throw new IOException("rename(" + oldPath + " => " + newPath + ")[" + options + "] client is closed");
        }

        if (log.isDebugEnabled()) {
            log.debug("rename({}) {} => {}", getClientChannel(), oldPath, newPath);
        }

        Buffer buffer = new ByteArrayBuffer(oldPath.length() + newPath.length() + Long.SIZE /* some extra fields */, false);
        buffer = putReferencedName(SftpConstants.SSH_FXP_RENAME, buffer, oldPath, 0);
        buffer = putReferencedName(SftpConstants.SSH_FXP_RENAME, buffer, newPath, 1);

        int numOptions = GenericUtils.size(options);
        int version = getVersion();
        if (version >= SftpConstants.SFTP_V5) {
            int opts = 0;
            if (numOptions > 0) {
                for (CopyMode opt : options) {
                    switch (opt) {
                        case Atomic:
                            opts |= SftpConstants.SSH_FXP_RENAME_ATOMIC;
                            break;
                        case Overwrite:
                            opts |= SftpConstants.SSH_FXP_RENAME_OVERWRITE;
                            break;
                        default: // do nothing
                    }
                }
            }
            buffer.putInt(opts);
        } else if (numOptions > 0) {
            throw new UnsupportedOperationException("rename(" + oldPath + " => " + newPath + ")"
                                                    + " - copy options can not be used with this SFTP version: " + options);
        }
        checkCommandStatus(SftpConstants.SSH_FXP_RENAME, buffer);
    }

    @Override
    public int read(Handle handle, long fileOffset, byte[] dst, int dstOffset, int len, AtomicReference<Boolean> eofSignalled)
            throws IOException {
        if (!isOpen()) {
            throw new IOException("read(" + handle + "/" + fileOffset + ")[" + dstOffset + "/" + len + "] client is closed");
        }

        byte[] id = Objects.requireNonNull(handle, "No handle").getIdentifier();
        Buffer buffer = new ByteArrayBuffer(id.length + Long.SIZE /* some extra fields */, false);
        buffer.putBytes(id);
        buffer.putLong(fileOffset);
        buffer.putUInt(len);
        return checkData(SftpConstants.SSH_FXP_READ, buffer, dstOffset, dst, eofSignalled);
    }

    protected int checkData(
            int cmd, Buffer request, int dstOffset, byte[] dst, AtomicReference<Boolean> eofSignalled)
            throws IOException {
        return checkDataResponse(rpc(cmd, request), dstOffset, dst, eofSignalled);
    }

    protected int checkDataResponse(SftpResponse response, int dstoff, byte[] dst, AtomicReference<Boolean> eofSignalled)
            throws IOException {
        switch (response.getType()) {
            case SftpConstants.SSH_FXP_DATA:
                Buffer buffer = response.getBuffer();
                int len = buffer.getInt();
                ValidateUtils.checkTrue(len >= 0, "Invalid response data len: %d", len);
                buffer.getRawBytes(dst, dstoff, len);
                Boolean indicator = SftpHelper.getEndOfFileIndicatorValue(buffer, getVersion());
                if (log.isTraceEnabled()) {
                    log.trace("checkDataResponse({}][id={}] {} offset={}, len={}, EOF={}", getClientChannel(),
                            SftpConstants.getCommandMessageName(response.getCmd()), response.getId(), dstoff, len, indicator);
                }
                if (eofSignalled != null) {
                    eofSignalled.set(indicator);
                }

                return len;
            case SftpConstants.SSH_FXP_STATUS:
                SftpStatus status = SftpStatus.parse(response);

                if (status.getStatusCode() == SftpConstants.SSH_FX_EOF) {
                    if (log.isTraceEnabled()) {
                        log.trace("checkDataResponse({})[id={}] {} status: {}", getClientChannel(), response.getId(),
                                SftpConstants.getCommandMessageName(response.getCmd()), status);
                    }
                    return -1;
                }

                throwStatusException(response.getCmd(), response.getId(), status);
                return 0;
            default:
                return handleUnknownDataPacket(response);
        }
    }

    protected int handleUnknownDataPacket(SftpResponse response) throws IOException {
        IOException err = handleUnexpectedPacket(SftpConstants.SSH_FXP_DATA, response);
        if (err != null) {
            throw err;
        }

        return 0;
    }

    @Override
    public void errorData(byte[] buf, int start, int len) throws IOException {
        /*
         * The protocol does not specify how to handle such data but we are lenient and ignore it - similar to
         * /dev/null
         */
        if (errorDataHandler != null) {
            errorDataHandler.errorData(buf, start, len);
        }
    }

    @Override
    public void write(Handle handle, long fileOffset, byte[] src, int srcOffset, int len) throws IOException {
        // do some bounds checking first
        if ((fileOffset < 0L) || (srcOffset < 0) || (len < 0)) {
            throw new IllegalArgumentException("write(" + handle + ") please ensure all parameters "
                                               + " are non-negative values: file-offset=" + fileOffset
                                               + ", src-offset=" + srcOffset + ", len=" + len);
        }
        if ((srcOffset + len) > src.length) {
            throw new IllegalArgumentException("write(" + handle + ")"
                                               + " cannot read bytes " + srcOffset + " to " + (srcOffset + len)
                                               + " when array is only of length " + src.length);
        }
        if (!isOpen()) {
            throw new IOException("write(" + handle + "/" + fileOffset + ")[" + srcOffset + "/" + len + "] client is closed");
        }

        boolean traceEnabled = log.isTraceEnabled();
        Channel clientChannel = getClientChannel();
        int chunkSize = SftpModuleProperties.WRITE_CHUNK_SIZE.getRequired(clientChannel);
        ValidateUtils.checkState(chunkSize > ByteArrayBuffer.DEFAULT_SIZE, "Write chunk size too small: %d", chunkSize);

        byte[] id = Objects.requireNonNull(handle, "No handle").getIdentifier();
        // NOTE: we don't want to filter out zero-length write requests
        int remLen = len;
        do {
            int writeSize = Math.min(remLen, chunkSize);
            Buffer buffer = new ByteArrayBuffer(id.length + writeSize + Long.SIZE /* some extra fields */, false);
            buffer.putBytes(id);
            buffer.putLong(fileOffset);
            buffer.putBytes(src, srcOffset, writeSize);

            if (traceEnabled) {
                log.trace("write({}) handle={}, file-offset={}, buf-offset={}, writeSize={}, remLen={}",
                        clientChannel, handle, fileOffset, srcOffset, writeSize, remLen - writeSize);
            }

            checkCommandStatus(SftpConstants.SSH_FXP_WRITE, buffer);

            fileOffset += writeSize;
            srcOffset += writeSize;
            remLen -= writeSize;
        } while (remLen > 0);
    }

    @Override
    public void mkdir(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("mkdir(" + path + ") client is closed");
        }

        if (log.isDebugEnabled()) {
            log.debug("mkdir({}): send SSH_FXP_MKDIR {}", getClientChannel(), path);
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE /* some extra fields */, false);
        buffer = putReferencedName(SftpConstants.SSH_FXP_MKDIR, buffer, path, 0);
        buffer.putUInt(0L);

        int version = getVersion();
        if (version != SftpConstants.SFTP_V3) {
            buffer.putByte((byte) 0);
        }

        checkCommandStatus(SftpConstants.SSH_FXP_MKDIR, buffer);
    }

    @Override
    public void rmdir(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("rmdir(" + path + ") client is closed");
        }

        if (log.isDebugEnabled()) {
            log.debug("rmdir({}): send SSH_FXP_RMDIR {}", getClientChannel(), path);
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE /* some extra fields */, false);
        buffer = putReferencedName(SftpConstants.SSH_FXP_RMDIR, buffer, path, 0);
        checkCommandStatus(SftpConstants.SSH_FXP_RMDIR, buffer);
    }

    @Override
    public CloseableHandle openDir(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("openDir(" + path + ") client is closed");
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE /* some extra fields */, false);
        buffer = putReferencedName(SftpConstants.SSH_FXP_OPENDIR, buffer, path, 0);

        if (log.isDebugEnabled()) {
            log.debug("openDir({}): send SSH_FXP_OPENDIR {}", getClientChannel(), path);
        }
        CloseableHandle handle = new DefaultCloseableHandle(this, path, checkHandle(SftpConstants.SSH_FXP_OPENDIR, buffer));
        if (log.isTraceEnabled()) {
            log.trace("openDir({})[{}]: {}", getClientChannel(), path, handle);
        }

        return handle;
    }

    @Override
    public List<DirEntry> readDir(Handle handle, AtomicReference<Boolean> eolIndicator) throws IOException {
        if (eolIndicator != null) {
            eolIndicator.set(null); // assume unknown information
        }
        if (!isOpen()) {
            throw new IOException("readDir(" + handle + ") client is closed");
        }

        byte[] id = Objects.requireNonNull(handle, "No handle").getIdentifier();
        Buffer buffer = new ByteArrayBuffer(id.length + Byte.SIZE /* some extra fields */, false);
        buffer.putBytes(id);

        if (log.isDebugEnabled()) {
            log.debug("readDir({})[{}]: send SSH_FXP_READDIR", getClientChannel(), handle);
        }
        return checkDirResponse(rpc(SftpConstants.SSH_FXP_READDIR, buffer), eolIndicator);
    }

    protected List<DirEntry> checkDirResponse(SftpResponse response, AtomicReference<Boolean> eolIndicator)
            throws IOException {
        if (eolIndicator != null) {
            eolIndicator.set(null); // assume unknown
        }

        boolean traceEnabled = log.isTraceEnabled();
        switch (response.getType()) {
            case SftpConstants.SSH_FXP_NAME:
                ClientChannel channel = getClientChannel();
                Buffer buffer = response.getBuffer();
                int cmd = response.getCmd();
                int count = buffer.getInt();
                int version = getVersion();
                // Protect against malicious or corrupted packets
                if ((count < 0) || (count > SshConstants.SSH_REQUIRED_PAYLOAD_PACKET_LENGTH_SUPPORT)) {
                    log.error("checkDirResponse({})[id={}] illogical dir entries count: {}", channel, response.getId(), count);
                    throw new SshException("Illogical dir entries count: " + count);
                }

                boolean debugEnabled = log.isDebugEnabled();
                if (debugEnabled) {
                    log.debug("checkDirResponse({})[id={}] reading {} entries", channel, response.getId(), count);
                }

                List<DirEntry> entries = new ArrayList<>(count);
                AtomicInteger nameIndex = new AtomicInteger(0);
                for (int index = 1; index <= count; index++) {
                    String name = getReferencedName(cmd, buffer, nameIndex.getAndIncrement());
                    String longName = null;
                    if (version == SftpConstants.SFTP_V3) {
                        longName = getReferencedName(cmd, buffer, nameIndex.getAndIncrement());
                    }

                    Attributes attrs = SftpHelper.complete(readAttributes(cmd, buffer, nameIndex), longName);
                    if (traceEnabled) {
                        log.trace("checkDirResponse({})[id={}][{}/{}] ({})[{}]: {}", channel, response.getId(), index, count,
                                name, longName, attrs);
                    }
                    entries.add(new DirEntry(name, longName, attrs));
                }

                Boolean indicator = SftpHelper.getEndOfListIndicatorValue(buffer, version);
                if (eolIndicator != null) {
                    eolIndicator.set(indicator);
                }

                if (debugEnabled) {
                    log.debug("checkDirResponse({})[id={}] read count={}, eol={}", channel, response.getId(), entries.size(),
                            indicator);
                }
                return entries;
            case SftpConstants.SSH_FXP_STATUS:
                SftpStatus status = SftpStatus.parse(response);

                if (status.getStatusCode() != SftpConstants.SSH_FX_EOF) {
                    throwStatusException(response.getCmd(), response.getId(), status);
                } else if (traceEnabled) {
                    log.trace("checkDirResponse({})[id={}] - status: {}", getClientChannel(), response.getId(), status);
                }
                return null;
            default:
                return handleUnknownDirListingPacket(response);
        }
    }

    protected List<DirEntry> handleUnknownDirListingPacket(SftpResponse response)
            throws IOException {
        IOException err = handleUnexpectedPacket(SftpConstants.SSH_FXP_NAME, response);
        if (err != null) {
            throw err;
        }
        return Collections.emptyList();
    }

    /**
     * @param  expected    The expected packet type
     * @param  response    The actual {@link SftpResponse} received
     * @return             The exception to throw - if {@code null} then implementor assumed to handle the exception
     *                     internal. Otherwise, the exception is re-thrown
     * @throws IOException If failed to handle the exception internally
     */
    protected IOException handleUnexpectedPacket(int expected, SftpResponse response)
            throws IOException {
        return new SshException(
                "Unexpected SFTP packet received while awaiting " + SftpConstants.getCommandMessageName(expected)
                                + " response to " + SftpConstants.getCommandMessageName(response.getCmd()) + ": type="
                                + SftpConstants.getCommandMessageName(response.getType()) + ", id=" + response.getId()
                                + ", length=" + response.getLength());
    }

    @Override
    public String canonicalPath(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("canonicalPath(" + path + ") client is closed");
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE, false);
        buffer = putReferencedName(SftpConstants.SSH_FXP_REALPATH, buffer, path, 0);
        if (log.isDebugEnabled()) {
            log.debug("canonicalPath({}): send SSH_FXP_REALPATH {}", getClientChannel(), path);
        }
        return checkOneName(SftpConstants.SSH_FXP_REALPATH, buffer);
    }

    @Override
    public Attributes stat(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("stat(" + path + ") client is closed");
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE, false);
        buffer = putReferencedName(SftpConstants.SSH_FXP_STAT, buffer, path, 0);

        int version = getVersion();
        if (version >= SftpConstants.SFTP_V4) {
            buffer.putInt(SftpConstants.SSH_FILEXFER_ATTR_ALL);
        }

        if (log.isDebugEnabled()) {
            log.debug("stat({}): send SSH_FXP_STAT {}", getClientChannel(), path);
        }
        return checkAttributes(SftpConstants.SSH_FXP_STAT, buffer);
    }

    @Override
    public Attributes lstat(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("lstat(" + path + ") client is closed");
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE, false);
        buffer = putReferencedName(SftpConstants.SSH_FXP_LSTAT, buffer, path, 0);

        int version = getVersion();
        if (version >= SftpConstants.SFTP_V4) {
            buffer.putInt(SftpConstants.SSH_FILEXFER_ATTR_ALL);
        }

        if (log.isDebugEnabled()) {
            log.debug("stat({}): send SSH_FXP_LSTAT {}", getClientChannel(), path);
        }
        return checkAttributes(SftpConstants.SSH_FXP_LSTAT, buffer);
    }

    @Override
    public Attributes stat(Handle handle) throws IOException {
        if (!isOpen()) {
            throw new IOException("stat(" + handle + ") client is closed");
        }

        byte[] id = Objects.requireNonNull(handle, "No handle").getIdentifier();
        Buffer buffer = new ByteArrayBuffer(id.length + Byte.SIZE /* a bit extra */, false);
        buffer.putBytes(id);

        int version = getVersion();
        if (version >= SftpConstants.SFTP_V4) {
            buffer.putInt(SftpConstants.SSH_FILEXFER_ATTR_ALL);
        }

        if (log.isDebugEnabled()) {
            log.debug("stat({}): send SSH_FXP_FSTAT {}", getClientChannel(), handle);
        }
        return checkAttributes(SftpConstants.SSH_FXP_FSTAT, buffer);
    }

    @Override
    public void setStat(String path, Attributes attributes) throws IOException {
        if (!isOpen()) {
            throw new IOException("setStat(" + path + ")[" + attributes + "] client is closed");
        }

        if (log.isDebugEnabled()) {
            log.debug("setStat({})[{}]: {}", getClientChannel(), path, attributes);
        }

        Buffer buffer = new ByteArrayBuffer();
        buffer = putReferencedName(SftpConstants.SSH_FXP_SETSTAT, buffer, path, 0);
        buffer = writeAttributes(SftpConstants.SSH_FXP_SETSTAT, buffer, attributes);
        if (log.isDebugEnabled()) {
            log.debug("setStat({}): send SSH_FXP_SETSTAT {}", getClientChannel(), path);
        }
        checkCommandStatus(SftpConstants.SSH_FXP_SETSTAT, buffer);
    }

    @Override
    public void setStat(Handle handle, Attributes attributes) throws IOException {
        if (!isOpen()) {
            throw new IOException("setStat(" + handle + ")[" + attributes + "] client is closed");
        }

        if (log.isDebugEnabled()) {
            log.debug("setStat({})[{}]: {}", getClientChannel(), handle, attributes);
        }
        byte[] id = Objects.requireNonNull(handle, "No handle").getIdentifier();
        Buffer buffer = new ByteArrayBuffer(id.length + (2 * Long.SIZE) /* some extras */, false);
        buffer.putBytes(id);
        buffer = writeAttributes(SftpConstants.SSH_FXP_FSETSTAT, buffer, attributes);
        if (log.isDebugEnabled()) {
            log.debug("setStat({}): send SSH_FXP_FSETSTAT {}", getClientChannel(), handle);
        }
        checkCommandStatus(SftpConstants.SSH_FXP_FSETSTAT, buffer);
    }

    @Override
    public String readLink(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("readLink(" + path + ") client is closed");
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE /* some extra fields */, false);
        buffer = putReferencedName(SftpConstants.SSH_FXP_READLINK, buffer, path, 0);
        if (log.isDebugEnabled()) {
            log.debug("readLink({}): send SSH_FXP_READLINK {}", getClientChannel(), path);
        }
        return checkOneName(SftpConstants.SSH_FXP_READLINK, buffer);
    }

    @Override
    public void link(String linkPath, String targetPath, boolean symbolic) throws IOException {
        if (!isOpen()) {
            throw new IOException("link(" + linkPath + " => " + targetPath + ")[symbolic=" + symbolic + "] client is closed");
        }

        int version = getVersion();
        int cmd = version < SftpConstants.SFTP_V6 ? SftpConstants.SSH_FXP_SYMLINK : SftpConstants.SSH_FXP_LINK;
        if (log.isDebugEnabled()) {
            log.debug("link({})[symbolic={}] send {} {} => {}", getClientChannel(), symbolic,
                    SshConstants.getCommandMessageName(cmd), linkPath, targetPath);
        }

        Buffer buffer = new ByteArrayBuffer(linkPath.length() + targetPath.length() + Long.SIZE /* some extra fields */, false);
        if (version < SftpConstants.SFTP_V6) {
            if (!symbolic) {
                throw new UnsupportedOperationException("Hard links are not supported in sftp v" + version + ", need SFTPv6");
            }
            buffer = putReferencedName(cmd, buffer, targetPath, 0);
            buffer = putReferencedName(cmd, buffer, linkPath, 1);
        } else {
            buffer = putReferencedName(cmd, buffer, targetPath, 0);
            buffer = putReferencedName(cmd, buffer, linkPath, 1);
            buffer.putBoolean(symbolic);
        }
        checkCommandStatus(cmd, buffer);
    }

    @Override
    public void lock(Handle handle, long offset, long length, int mask) throws IOException {
        if (!isOpen()) {
            throw new IOException(
                    "lock(" + handle + ")[offset=" + offset + ", length=" + length + ", mask=0x" + Integer.toHexString(mask)
                                  + "] client is closed");
        }
        int version = getVersion();
        if (version < SftpConstants.SFTP_V6) {
            throw new UnsupportedOperationException("File locks are not supported in sftp v" + version + ", need SFTPv6");
        }
        byte[] id = Objects.requireNonNull(handle, "No handle").getIdentifier();
        Buffer buffer = new ByteArrayBuffer(id.length + Long.SIZE /* a bit extra */, false);
        buffer.putBytes(id);
        buffer.putLong(offset);
        buffer.putLong(length);
        buffer.putInt(mask);
        if (log.isDebugEnabled()) {
            log.debug("lock({})[{}] send SSH_FXP_BLOCK offset={}, length={}, mask=0x{}", getClientChannel(), handle, offset,
                    length, Integer.toHexString(mask));
        }
        checkCommandStatus(SftpConstants.SSH_FXP_BLOCK, buffer);
    }

    @Override
    public void unlock(Handle handle, long offset, long length) throws IOException {
        if (!isOpen()) {
            throw new IOException("unlock" + handle + ")[offset=" + offset + ", length=" + length + "] client is closed");
        }
        int version = getVersion();
        if (version < SftpConstants.SFTP_V6) {
            throw new UnsupportedOperationException("File locks are not supported in sftp v" + version + ", need SFTPv6");
        }

        byte[] id = Objects.requireNonNull(handle, "No handle").getIdentifier();
        Buffer buffer = new ByteArrayBuffer(id.length + Long.SIZE /* a bit extra */, false);
        buffer.putBytes(id);
        buffer.putLong(offset);
        buffer.putLong(length);
        if (log.isDebugEnabled()) {
            log.debug("unlock({})[{}] send SSH_FXP_UNBLOCK offset={}, length={}", getClientChannel(), handle, offset, length);
        }
        checkCommandStatus(SftpConstants.SSH_FXP_UNBLOCK, buffer);
    }

    @Override
    public Iterable<DirEntry> readDir(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("readDir(" + path + ") client is closed");
        }

        return new SftpIterableDirEntry(this, path);
    }

    @Override
    public Iterable<DirEntry> listDir(Handle handle) throws IOException {
        if (!isOpen()) {
            throw new IOException("listDir(" + handle + ") client is closed");
        }

        return new StfpIterableDirHandle(this, handle);
    }

    @Override
    public FileChannel openRemoteFileChannel(String path, Collection<OpenMode> modes) throws IOException {
        return new SftpRemotePathChannel(path, this, false, GenericUtils.isEmpty(modes) ? DEFAULT_CHANNEL_MODES : modes);
    }

    @Override
    public InputStream read(String path, int bufferSize, Collection<OpenMode> mode) throws IOException {
        if (bufferSize <= 0) {
            bufferSize = getReadBufferSize();
        }
        if (bufferSize < MIN_READ_BUFFER_SIZE) {
            throw new IllegalArgumentException("Insufficient read buffer size: " + bufferSize + ", min.="
                                               + MIN_READ_BUFFER_SIZE);
        }

        if (!isOpen()) {
            throw new IOException("write(" + path + ")[" + mode + "] size=" + bufferSize + ": client is closed");
        }

        return new SftpInputStreamAsync(this, bufferSize, path, mode);
    }

    @Override
    public OutputStream write(String path, int bufferSize, Collection<OpenMode> mode) throws IOException {
        if (bufferSize <= 0) {
            bufferSize = getWriteBufferSize();
        }
        if (bufferSize < MIN_WRITE_BUFFER_SIZE) {
            throw new IllegalArgumentException("Insufficient write buffer size: " + bufferSize + ", min.="
                                               + MIN_WRITE_BUFFER_SIZE);
        }

        if (!isOpen()) {
            throw new IOException("write(" + path + ")[" + mode + "] size=" + bufferSize + ": client is closed");
        }

        return new SftpOutputStreamAsync(this, bufferSize, path, mode);
    }

    protected int getReadBufferSize() {
        return (int) getClientChannel().getLocalWindow().getPacketSize() - 13;
    }

    protected int getWriteBufferSize() {
        return (int) getClientChannel().getRemoteWindow().getPacketSize() - 13;
    }

}
