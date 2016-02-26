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
package org.apache.sshd.client.subsystem.sftp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.subsystem.AbstractSubsystemClient;
import org.apache.sshd.client.subsystem.sftp.extensions.BuiltinSftpClientExtensions;
import org.apache.sshd.client.subsystem.sftp.extensions.SftpClientExtension;
import org.apache.sshd.client.subsystem.sftp.extensions.SftpClientExtensionFactory;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.subsystem.sftp.SftpException;
import org.apache.sshd.common.subsystem.sftp.SftpHelper;
import org.apache.sshd.common.subsystem.sftp.SftpUniversalOwnerAndGroup;
import org.apache.sshd.common.subsystem.sftp.extensions.ParserUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;


/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSftpClient extends AbstractSubsystemClient implements SftpClient, RawSftpClient {
    private final AtomicReference<Map<String, Object>> parsedExtensionsHolder = new AtomicReference<>(null);

    protected AbstractSftpClient() {
        super();
    }

    @Override
    public Channel getChannel() {
        return getClientChannel();
    }

    @Override
    public String getName() {
        return SftpConstants.SFTP_SUBSYSTEM_NAME;
    }

    @Override
    public CloseableHandle open(String path) throws IOException {
        return open(path, Collections.<OpenMode>emptySet());
    }

    @Override
    public CloseableHandle open(String path, OpenMode... options) throws IOException {
        return open(path, GenericUtils.of(options));
    }

    @Override
    public void rename(String oldPath, String newPath) throws IOException {
        rename(oldPath, newPath, Collections.<CopyMode>emptySet());
    }

    @Override
    public void rename(String oldPath, String newPath, CopyMode... options) throws IOException {
        rename(oldPath, newPath, GenericUtils.of(options));
    }

    @Override
    public InputStream read(String path) throws IOException {
        return read(path, DEFAULT_READ_BUFFER_SIZE);
    }

    @Override
    public InputStream read(String path, int bufferSize) throws IOException {
        return read(path, bufferSize, EnumSet.of(OpenMode.Read));
    }

    @Override
    public InputStream read(String path, OpenMode... mode) throws IOException {
        return read(path, DEFAULT_READ_BUFFER_SIZE, mode);
    }

    @Override
    public InputStream read(String path, int bufferSize, OpenMode... mode) throws IOException {
        return read(path, bufferSize, GenericUtils.of(mode));
    }

    @Override
    public InputStream read(String path, Collection<OpenMode> mode) throws IOException {
        return read(path, DEFAULT_READ_BUFFER_SIZE, mode);
    }

    @Override
    public OutputStream write(String path) throws IOException {
        return write(path, DEFAULT_WRITE_BUFFER_SIZE);
    }

    @Override
    public OutputStream write(String path, int bufferSize) throws IOException {
        return write(path, bufferSize, EnumSet.of(OpenMode.Write, OpenMode.Create, OpenMode.Truncate));
    }

    @Override
    public OutputStream write(String path, OpenMode... mode) throws IOException {
        return write(path, DEFAULT_WRITE_BUFFER_SIZE, mode);
    }

    @Override
    public OutputStream write(String path, Collection<OpenMode> mode) throws IOException {
        return write(path, DEFAULT_WRITE_BUFFER_SIZE, mode);
    }

    @Override
    public OutputStream write(String path, int bufferSize, OpenMode... mode) throws IOException {
        return write(path, bufferSize, GenericUtils.of(mode));
    }

    @Override
    public void write(Handle handle, long fileOffset, byte[] src) throws IOException {
        write(handle, fileOffset, src, 0, src.length);
    }

    @Override
    public void symLink(String linkPath, String targetPath) throws IOException {
        link(linkPath, targetPath, true);
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
    public SftpClientExtension getExtension(String extensionName) {
        return getExtension(BuiltinSftpClientExtensions.fromName(extensionName));
    }

    protected SftpClientExtension getExtension(SftpClientExtensionFactory factory) {
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
     * Sends the specified command, waits for the response and then invokes {@link #checkResponseStatus(int, Buffer)}
     * @param cmd The command to send
     * @param request The request {@link Buffer}
     * @throws IOException If failed to send, receive or check the returned status
     * @see #send(int, Buffer)
     * @see #receive(int)
     * @see #checkResponseStatus(int, Buffer)
     */
    protected void checkCommandStatus(int cmd, Buffer request) throws IOException {
        int reqId = send(cmd, request);
        Buffer response = receive(reqId);
        checkResponseStatus(cmd, response);
    }

    /**
     * Checks if the incoming response is an {@code SSH_FXP_STATUS} one,
     * and if so whether the substatus is {@code SSH_FX_OK}.
     *
     * @param cmd The sent command opcode
     * @param buffer The received response {@link Buffer}
     * @throws IOException If response does not carry a status or carries
     * a bad status code
     * @see #checkResponseStatus(int, int, int, String, String)
     */
    protected void checkResponseStatus(int cmd, Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        if (type == SftpConstants.SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            checkResponseStatus(cmd, id, substatus, msg, lang);
        } else {
            handleUnexpectedPacket(cmd, SftpConstants.SSH_FXP_STATUS, id, type, length, buffer);
        }
    }

    /**
     * @param cmd The sent command opcode
     * @param id The request id
     * @param substatus The sub-status value
     * @param msg The message
     * @param lang The language
     * @throws IOException if the sub-status is not {@code SSH_FX_OK}
     * @see #throwStatusException(int, int, int, String, String)
     */
    protected void checkResponseStatus(int cmd, int id, int substatus, String msg, String lang) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("checkResponseStatus({})[id={}] cmd={} status={} lang={} msg={}",
                      getClientChannel(), id, SftpConstants.getCommandMessageName(cmd),
                      SftpConstants.getStatusName(substatus), lang, msg);
        }

        if (substatus != SftpConstants.SSH_FX_OK) {
            throwStatusException(cmd, id, substatus, msg, lang);
        }
    }

    protected void throwStatusException(int cmd, int id, int substatus, String msg, String lang) throws IOException {
        throw new SftpException(substatus, msg);
    }

    /**
     * @param cmd Command to be sent
     * @param request The {@link Buffer} containing the request
     * @return The received handle identifier
     * @throws IOException If failed to send/receive or process the response
     * @see #send(int, Buffer)
     * @see #receive(int)
     * @see #checkHandleResponse(int, Buffer)
     */
    protected byte[] checkHandle(int cmd, Buffer request) throws IOException {
        int reqId = send(cmd, request);
        Buffer response = receive(reqId);
        return checkHandleResponse(cmd, response);
    }

    protected byte[] checkHandleResponse(int cmd, Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        if (type == SftpConstants.SSH_FXP_HANDLE) {
            return ValidateUtils.checkNotNullAndNotEmpty(buffer.getBytes(), "Null/empty handle in buffer", GenericUtils.EMPTY_OBJECT_ARRAY);
        }

        if (type == SftpConstants.SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (log.isTraceEnabled()) {
                log.trace("checkHandleResponse({})[id={}] {} - status: {} [{}] {}",
                          getClientChannel(), id, SftpConstants.getCommandMessageName(cmd),
                          SftpConstants.getStatusName(substatus), lang, msg);
            }
            throwStatusException(cmd, id, substatus, msg, lang);
        }

        return handleUnexpectedHandlePacket(cmd, id, type, length, buffer);
    }

    protected byte[] handleUnexpectedHandlePacket(int cmd, int id, int type, int length, Buffer buffer) throws IOException {
        handleUnexpectedPacket(cmd, SftpConstants.SSH_FXP_HANDLE, id, type, length, buffer);
        throw new SshException("No handling for unexpected handle packet id=" + id
                             + ", type=" + SftpConstants.getCommandMessageName(type) + ", length=" + length);
    }

    /**
     * @param cmd Command to be sent
     * @param request Request {@link Buffer}
     * @return The decoded response {@code Attributes}
     * @throws IOException If failed to send/receive or process the response
     * @see #send(int, Buffer)
     * @see #receive(int)
     * @see #checkAttributesResponse(int, Buffer)
     */
    protected Attributes checkAttributes(int cmd, Buffer request) throws IOException {
        int reqId = send(cmd, request);
        Buffer response = receive(reqId);
        return checkAttributesResponse(cmd, response);
    }

    protected Attributes checkAttributesResponse(int cmd, Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        if (type == SftpConstants.SSH_FXP_ATTRS) {
            return readAttributes(buffer);
        }

        if (type == SftpConstants.SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (log.isTraceEnabled()) {
                log.trace("checkAttributesResponse()[id={}] {} - status: {} [{}] {}",
                          getClientChannel(), id, SftpConstants.getCommandMessageName(cmd),
                          SftpConstants.getStatusName(substatus), lang, msg);
            }
            throwStatusException(cmd, id, substatus, msg, lang);
        }

        return handleUnexpectedAttributesPacket(cmd, id, type, length, buffer);
    }

    protected Attributes handleUnexpectedAttributesPacket(int cmd, int id, int type, int length, Buffer buffer) throws IOException {
        IOException err = handleUnexpectedPacket(cmd, SftpConstants.SSH_FXP_ATTRS, id, type, length, buffer);
        if (err != null) {
            throw err;
        }

        return null;
    }

    /**
     * @param cmd Command to be sent
     * @param request The request {@link Buffer}
     * @return The retrieved name
     * @throws IOException If failed to send/receive or process the response
     * @see #send(int, Buffer)
     * @see #receive(int)
     * @see #checkOneNameResponse(int, Buffer)
     */
    protected String checkOneName(int cmd, Buffer request) throws IOException {
        int reqId = send(cmd, request);
        Buffer response = receive(reqId);
        return checkOneNameResponse(cmd, response);
    }

    protected String checkOneNameResponse(int cmd, Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        if (type == SftpConstants.SSH_FXP_NAME) {
            int len = buffer.getInt();
            if (len != 1) {
                throw new SshException("SFTP error: received " + len + " names instead of 1");
            }
            String name = buffer.getString();
            String longName = null;
            int version = getVersion();
            if (version == SftpConstants.SFTP_V3) {
                longName = buffer.getString();
            }

            Attributes attrs = readAttributes(buffer);
            Boolean indicator = SftpHelper.getEndOfListIndicatorValue(buffer, version);
            // TODO decide what to do if not-null and not TRUE
            if (log.isTraceEnabled()) {
                log.trace("checkOneNameResponse({})[id={}] {} ({})[{}] eol={}: {}",
                          getClientChannel(), id, SftpConstants.getCommandMessageName(cmd),
                          name, longName, indicator, attrs);
            }
            return name;
        }

        if (type == SftpConstants.SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (log.isTraceEnabled()) {
                log.trace("checkOneNameResponse({})[id={}] {} status: {} [{}] {}",
                          getClientChannel(), id, SftpConstants.getCommandMessageName(cmd),
                          SftpConstants.getStatusName(substatus), lang, msg);
            }

            throwStatusException(cmd, id, substatus, msg, lang);
        }

        return handleUnknownOneNamePacket(cmd, id, type, length, buffer);
    }

    protected String handleUnknownOneNamePacket(int cmd, int id, int type, int length, Buffer buffer) throws IOException {
        IOException err = handleUnexpectedPacket(cmd, SftpConstants.SSH_FXP_NAME, id, type, length, buffer);
        if (err != null) {
            throw err;
        }

        return null;
    }

    protected Attributes readAttributes(Buffer buffer) throws IOException {
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
                long allocSize = buffer.getLong();    // TODO handle allocation size
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
                FileTime attrsChangedTime = SftpHelper.readTime(buffer, version, flags);    // TODO the last time the file attributes were changed
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
                    String untranslated = buffer.getString(); // TODO: handle untranslated-name
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

    protected void writeAttributes(Buffer buffer, Attributes attributes) throws IOException {
        int version = getVersion();
        int flagsMask = 0;
        Collection<Attribute> flags = ValidateUtils.checkNotNull(attributes, "No attributes").getFlags();
        if (version == SftpConstants.SFTP_V3) {
            for (Attribute a : flags) {
                switch (a) {
                    case Size:
                        flagsMask |= SftpConstants.SSH_FILEXFER_ATTR_SIZE;
                        break;
                    case UidGid:
                        flagsMask |= SftpConstants.SSH_FILEXFER_ATTR_UIDGID;
                        break;
                    case Perms:
                        flagsMask |= SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS;
                        break;
                    case AccessTime:
                        if (flags.contains(Attribute.ModifyTime)) {
                            flagsMask |= SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME;
                        }
                        break;
                    case ModifyTime:
                        if (flags.contains(Attribute.AccessTime)) {
                            flagsMask |= SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME;
                        }
                        break;
                    case Extensions:
                        flagsMask |= SftpConstants.SSH_FILEXFER_ATTR_EXTENDED;
                        break;
                    default:    // do nothing
                }
            }
            buffer.putInt(flagsMask);
            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_SIZE) != 0) {
                buffer.putLong(attributes.getSize());
            }
            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_UIDGID) != 0) {
                buffer.putInt(attributes.getUserId());
                buffer.putInt(attributes.getGroupId());
            }
            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
                buffer.putInt(attributes.getPermissions());
            }

            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME) != 0) {
                SftpHelper.writeTime(buffer, version, flagsMask, attributes.getAccessTime());
                SftpHelper.writeTime(buffer, version, flagsMask, attributes.getModifyTime());
            }
        } else if (version >= SftpConstants.SFTP_V4) {
            for (Attribute a : flags) {
                switch (a) {
                    case Size:
                        flagsMask |= SftpConstants.SSH_FILEXFER_ATTR_SIZE;
                        break;
                    case OwnerGroup:
                        flagsMask |= SftpConstants.SSH_FILEXFER_ATTR_OWNERGROUP;
                        break;
                    case Perms:
                        flagsMask |= SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS;
                        break;
                    case AccessTime:
                        flagsMask |= SftpConstants.SSH_FILEXFER_ATTR_ACCESSTIME;
                        break;
                    case ModifyTime:
                        flagsMask |= SftpConstants.SSH_FILEXFER_ATTR_MODIFYTIME;
                        break;
                    case CreateTime:
                        flagsMask |= SftpConstants.SSH_FILEXFER_ATTR_CREATETIME;
                        break;
                    case Acl:
                        flagsMask |= SftpConstants.SSH_FILEXFER_ATTR_ACL;
                        break;
                    case Extensions:
                        flagsMask |= SftpConstants.SSH_FILEXFER_ATTR_EXTENDED;
                        break;
                    default:    // do nothing
                }
            }
            buffer.putInt(flagsMask);
            buffer.putByte((byte) attributes.getType());
            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_SIZE) != 0) {
                buffer.putLong(attributes.getSize());
            }
            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_OWNERGROUP) != 0) {
                String owner = attributes.getOwner();
                buffer.putString(GenericUtils.isEmpty(owner) ? SftpUniversalOwnerAndGroup.Owner.getName() : owner);

                String group = attributes.getGroup();
                buffer.putString(GenericUtils.isEmpty(group) ? SftpUniversalOwnerAndGroup.Group.getName() : group);
            }
            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
                buffer.putInt(attributes.getPermissions());
            }
            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_ACCESSTIME) != 0) {
                SftpHelper.writeTime(buffer, version, flagsMask, attributes.getAccessTime());
            }
            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_CREATETIME) != 0) {
                SftpHelper.writeTime(buffer, version, flagsMask, attributes.getCreateTime());
            }
            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_MODIFYTIME) != 0) {
                SftpHelper.writeTime(buffer, version, flagsMask, attributes.getModifyTime());
            }
            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_ACL) != 0) {
                SftpHelper.writeACLs(buffer, version, attributes.getAcl());
            }

            // TODO: for v6+ add CTIME (see https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#page-21)
        } else {
            throw new UnsupportedOperationException("writeAttributes(" + attributes + ") unsupported version: " + version);
        }

        if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_EXTENDED) != 0) {
            SftpHelper.writeExtensions(buffer, attributes.getExtensions());
        }
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
        buffer.putString(path);
        int version = getVersion();
        int mode = 0;
        if (version == SftpConstants.SFTP_V3) {
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
                    default:    // do nothing
                }
            }
        } else {
            if (version >= SftpConstants.SFTP_V5) {
                int access = 0;
                if (options.contains(OpenMode.Read)) {
                    access |= SftpConstants.ACE4_READ_DATA | SftpConstants.ACE4_READ_ATTRIBUTES;
                }
                if (options.contains(OpenMode.Write)) {
                    access |= SftpConstants.ACE4_WRITE_DATA | SftpConstants.ACE4_WRITE_ATTRIBUTES;
                }
                if (options.contains(OpenMode.Append)) {
                    access |= SftpConstants.ACE4_APPEND_DATA;
                }
                buffer.putInt(access);
            }

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
        writeAttributes(buffer, new Attributes());

        CloseableHandle handle = new DefaultCloseableHandle(this, path, checkHandle(SftpConstants.SSH_FXP_OPEN, buffer));
        if (log.isTraceEnabled()) {
            log.trace("open({})[{}] options={}: {}", getClientSession(), path, options, handle);
        }
        return handle;
    }

    @Override
    public void close(Handle handle) throws IOException {
        if (!isOpen()) {
            throw new IOException("close(" + handle + ") client is closed");
        }

        if (log.isTraceEnabled()) {
            log.trace("close({}) {}", getClientSession(), handle);
        }

        byte[] id = ValidateUtils.checkNotNull(handle, "No handle").getIdentifier();
        Buffer buffer = new ByteArrayBuffer(id.length + Long.SIZE /* some extra fields */, false);
        buffer.putBytes(id);
        checkCommandStatus(SftpConstants.SSH_FXP_CLOSE, buffer);
    }

    @Override
    public void remove(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("remove(" + path + ") client is closed");
        }

        if (log.isDebugEnabled()) {
            log.debug("remove({}) {}", getClientSession(), path);
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE /* some extra fields */, false);
        buffer.putString(path);
        checkCommandStatus(SftpConstants.SSH_FXP_REMOVE, buffer);
    }

    @Override
    public void rename(String oldPath, String newPath, Collection<CopyMode> options) throws IOException {
        if (!isOpen()) {
            throw new IOException("rename(" + oldPath + " => " + newPath + ")[" + options + "] client is closed");
        }

        if (log.isDebugEnabled()) {
            log.debug("rename({}) {} => {}", getClientSession(), oldPath, newPath);
        }

        Buffer buffer = new ByteArrayBuffer(oldPath.length() + newPath.length() + Long.SIZE /* some extra fields */, false);
        buffer.putString(oldPath);
        buffer.putString(newPath);

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
                        default:    // do nothing
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

    @Override   // TODO make this a default method in Java 8
    public int read(Handle handle, long fileOffset, byte[] dst) throws IOException {
        return read(handle, fileOffset, dst, null);
    }

    @Override   // TODO make this a default method in Java 8
    public int read(Handle handle, long fileOffset, byte[] dst, AtomicReference<Boolean> eofSignalled) throws IOException {
        return read(handle, fileOffset, dst, 0, dst.length, eofSignalled);
    }

    @Override   // TODO make this a default method in Java 8
    public int read(Handle handle, long fileOffset, byte[] dst, int dstOffset, int len) throws IOException {
        return read(handle, fileOffset, dst, dstOffset, len, null);
    }

    @Override
    public int read(Handle handle, long fileOffset, byte[] dst, int dstOffset, int len, AtomicReference<Boolean> eofSignalled) throws IOException {
        if (eofSignalled != null) {
            eofSignalled.set(null);
        }

        if (!isOpen()) {
            throw new IOException("read(" + handle + "/" + fileOffset + ")[" + dstOffset + "/" + len + "] client is closed");
        }

        byte[] id = ValidateUtils.checkNotNull(handle, "No handle").getIdentifier();
        Buffer buffer = new ByteArrayBuffer(id.length + Long.SIZE /* some extra fields */, false);
        buffer.putBytes(id);
        buffer.putLong(fileOffset);
        buffer.putInt(len);
        return checkData(SftpConstants.SSH_FXP_READ, buffer, dstOffset, dst, eofSignalled);
    }

    protected int checkData(int cmd, Buffer request, int dstOffset, byte[] dst, AtomicReference<Boolean> eofSignalled) throws IOException {
        if (eofSignalled != null) {
            eofSignalled.set(null);
        }
        int reqId = send(cmd, request);
        Buffer response = receive(reqId);
        return checkDataResponse(cmd, response, dstOffset, dst, eofSignalled);
    }

    protected int checkDataResponse(int cmd, Buffer buffer, int dstoff, byte[] dst, AtomicReference<Boolean> eofSignalled) throws IOException {
        if (eofSignalled != null) {
            eofSignalled.set(null);
        }

        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        if (type == SftpConstants.SSH_FXP_DATA) {
            int len = buffer.getInt();
            buffer.getRawBytes(dst, dstoff, len);
            Boolean indicator = SftpHelper.getEndOfFileIndicatorValue(buffer, getVersion());
            if (log.isTraceEnabled()) {
                log.trace("checkDataResponse({}][id={}] {} offset={}, len={}, EOF={}",
                          getClientChannel(), SftpConstants.getCommandMessageName(cmd),
                          id, dstoff, len, indicator);
            }
            if (eofSignalled != null) {
                eofSignalled.set(indicator);
            }

            return len;
        }

        if (type == SftpConstants.SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (log.isTraceEnabled()) {
                log.trace("checkDataResponse({})[id={}] {} status: {} [{}] {}",
                          getClientChannel(), id, SftpConstants.getCommandMessageName(cmd),
                          SftpConstants.getStatusName(substatus), lang, msg);
            }

            if (substatus == SftpConstants.SSH_FX_EOF) {
                return -1;
            }

            throwStatusException(cmd, id, substatus, msg, lang);
        }

        return handleUnknownDataPacket(cmd, id, type, length, buffer);
    }

    protected int handleUnknownDataPacket(int cmd, int id, int type, int length, Buffer buffer) throws IOException {
        IOException err = handleUnexpectedPacket(cmd, SftpConstants.SSH_FXP_DATA, id, type, length, buffer);
        if (err != null) {
            throw err;
        }

        return 0;
    }

    @Override
    public void write(Handle handle, long fileOffset, byte[] src, int srcOffset, int len) throws IOException {
        // do some bounds checking first
        if ((fileOffset < 0) || (srcOffset < 0) || (len < 0)) {
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

        if (log.isTraceEnabled()) {
            log.trace("write({}) handle={}, file-offset={}, buf-offset={}, len={}",
                      getClientChannel(), handle, fileOffset, srcOffset, len);
        }

        byte[] id = ValidateUtils.checkNotNull(handle, "No handle").getIdentifier();
        Buffer buffer = new ByteArrayBuffer(id.length + len + Long.SIZE /* some extra fields */, false);
        buffer.putBytes(id);
        buffer.putLong(fileOffset);
        buffer.putBytes(src, srcOffset, len);
        checkCommandStatus(SftpConstants.SSH_FXP_WRITE, buffer);
    }

    @Override
    public void mkdir(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("mkdir(" + path + ") client is closed");
        }

        if (log.isDebugEnabled()) {
            log.debug("mkdir({}) {}", getClientSession(), path);
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE /* some extra fields */, false);
        buffer.putString(path);
        buffer.putInt(0);

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
            log.debug("rmdir({}) {}", getClientSession(), path);
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE /* some extra fields */, false);
        buffer.putString(path);
        checkCommandStatus(SftpConstants.SSH_FXP_RMDIR, buffer);
    }

    @Override
    public CloseableHandle openDir(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("openDir(" + path + ") client is closed");
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE /* some extra fields */, false);
        buffer.putString(path);

        CloseableHandle handle = new DefaultCloseableHandle(this, path, checkHandle(SftpConstants.SSH_FXP_OPENDIR, buffer));
        if (log.isTraceEnabled()) {
            log.trace("openDir({})[{}}: {}", getClientSession(), path, handle);
        }

        return handle;
    }

    @Override   // TODO in JDK-8 make this a default method
    public List<DirEntry> readDir(Handle handle) throws IOException {
        return readDir(handle, null);
    }

    @Override
    public List<DirEntry> readDir(Handle handle, AtomicReference<Boolean> eolIndicator) throws IOException {
        if (eolIndicator != null) {
            eolIndicator.set(null);    // assume unknown information
        }
        if (!isOpen()) {
            throw new IOException("readDir(" + handle + ") client is closed");
        }

        byte[] id = ValidateUtils.checkNotNull(handle, "No handle").getIdentifier();
        Buffer buffer = new ByteArrayBuffer(id.length + Byte.SIZE /* some extra fields */, false);
        buffer.putBytes(id);

        int cmdId = send(SftpConstants.SSH_FXP_READDIR, buffer);
        Buffer response = receive(cmdId);
        return checkDirResponse(SftpConstants.SSH_FXP_READDIR, response, eolIndicator);
    }

    protected List<DirEntry> checkDirResponse(int cmd, Buffer buffer, AtomicReference<Boolean> eolIndicator) throws IOException {
        if (eolIndicator != null) {
            eolIndicator.set(null);    // assume unknown
        }

        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        if (type == SftpConstants.SSH_FXP_NAME) {
            int len = buffer.getInt();
            int version = getVersion();
            ClientChannel channel = getClientChannel();
            if (log.isDebugEnabled()) {
                log.debug("checkDirResponse({}}[id={}] reading {} entries", channel, id, len);
            }

            List<DirEntry> entries = new ArrayList<DirEntry>(len);
            for (int i = 0; i < len; i++) {
                String name = buffer.getString();
                String longName = (version == SftpConstants.SFTP_V3) ? buffer.getString() : null;
                Attributes attrs = readAttributes(buffer);
                if (log.isTraceEnabled()) {
                    log.trace("checkDirResponse({})[id={}][{}] ({})[{}]: {}",
                              channel, id, i, name, longName, attrs);
                }

                entries.add(new DirEntry(name, longName, attrs));
            }

            Boolean indicator = SftpHelper.getEndOfListIndicatorValue(buffer, version);
            if (eolIndicator != null) {
                eolIndicator.set(indicator);
            }

            if (log.isDebugEnabled()) {
                log.debug("checkDirResponse({}}[id={}] read count={}, eol={}", channel, entries.size(), indicator);
            }
            return entries;
        }

        if (type == SftpConstants.SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (log.isTraceEnabled()) {
                log.trace("checkDirResponse({})[id={}] - status: {} [{}] {}",
                          getClientChannel(), id, SftpConstants.getStatusName(substatus), lang, msg);
            }

            if (substatus == SftpConstants.SSH_FX_EOF) {
                return null;
            }

            throwStatusException(cmd, id, substatus, msg, lang);
        }

        return handleUnknownDirListingPacket(cmd, id, type, length, buffer);
    }

    protected List<DirEntry> handleUnknownDirListingPacket(int cmd, int id, int type, int length, Buffer buffer) throws IOException {
        IOException err = handleUnexpectedPacket(cmd, SftpConstants.SSH_FXP_NAME, id, type, length, buffer);
        if (err != null) {
            throw err;
        }
        return Collections.emptyList();
    }

    protected IOException handleUnexpectedPacket(int cmd, int expected, int id, int type, int length, Buffer buffer) throws IOException {
        throw new SshException("Unexpected SFTP packet received while awaiting " + SftpConstants.getCommandMessageName(expected)
                        + " response to " + SftpConstants.getCommandMessageName(cmd)
                        + ": type=" + SftpConstants.getCommandMessageName(type) + ", id=" + id + ", length=" + length);
    }

    @Override
    public String canonicalPath(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("canonicalPath(" + path + ") client is closed");
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE, false);
        buffer.putString(path);
        return checkOneName(SftpConstants.SSH_FXP_REALPATH, buffer);
    }

    @Override
    public Attributes stat(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("stat(" + path + ") client is closed");
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE, false);
        buffer.putString(path);

        int version = getVersion();
        if (version >= SftpConstants.SFTP_V4) {
            buffer.putInt(SftpConstants.SSH_FILEXFER_ATTR_ALL);
        }

        return checkAttributes(SftpConstants.SSH_FXP_STAT, buffer);
    }

    @Override
    public Attributes lstat(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("lstat(" + path + ") client is closed");
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE, false);
        buffer.putString(path);

        int version = getVersion();
        if (version >= SftpConstants.SFTP_V4) {
            buffer.putInt(SftpConstants.SSH_FILEXFER_ATTR_ALL);
        }

        return checkAttributes(SftpConstants.SSH_FXP_LSTAT, buffer);
    }

    @Override
    public Attributes stat(Handle handle) throws IOException {
        if (!isOpen()) {
            throw new IOException("stat(" + handle + ") client is closed");
        }

        byte[] id = ValidateUtils.checkNotNull(handle, "No handle").getIdentifier();
        Buffer buffer = new ByteArrayBuffer(id.length + Byte.SIZE /* a bit extra */, false);
        buffer.putBytes(id);

        int version = getVersion();
        if (version >= SftpConstants.SFTP_V4) {
            buffer.putInt(SftpConstants.SSH_FILEXFER_ATTR_ALL);
        }

        return checkAttributes(SftpConstants.SSH_FXP_FSTAT, buffer);
    }

    @Override
    public void setStat(String path, Attributes attributes) throws IOException {
        if (!isOpen()) {
            throw new IOException("setStat(" + path + ")[" + attributes + "] client is closed");
        }

        if (log.isDebugEnabled()) {
            log.debug("setStat({})[{}]: {}", getClientSession(), path, attributes);
        }

        Buffer buffer = new ByteArrayBuffer();
        buffer.putString(path);
        writeAttributes(buffer, attributes);
        checkCommandStatus(SftpConstants.SSH_FXP_SETSTAT, buffer);
    }

    @Override
    public void setStat(Handle handle, Attributes attributes) throws IOException {
        if (!isOpen()) {
            throw new IOException("setStat(" + handle + ")[" + attributes + "] client is closed");
        }

        if (log.isDebugEnabled()) {
            log.debug("setStat({})[{}]: {}", getClientSession(), handle, attributes);
        }
        byte[] id = ValidateUtils.checkNotNull(handle, "No handle").getIdentifier();
        Buffer buffer = new ByteArrayBuffer(id.length + (2 * Long.SIZE) /* some extras */, false);
        buffer.putBytes(id);
        writeAttributes(buffer, attributes);
        checkCommandStatus(SftpConstants.SSH_FXP_FSETSTAT, buffer);
    }

    @Override
    public String readLink(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("readLink(" + path + ") client is closed");
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE /* some extra fields */, false);
        buffer.putString(path);
        return checkOneName(SftpConstants.SSH_FXP_READLINK, buffer);
    }

    @Override
    public void link(String linkPath, String targetPath, boolean symbolic) throws IOException {
        if (!isOpen()) {
            throw new IOException("link(" + linkPath + " => " + targetPath + ")[symbolic=" + symbolic + "] client is closed");
        }

        if (log.isDebugEnabled()) {
            log.debug("link({})[symbolic={}] {} => {}", getClientSession(), symbolic, linkPath, targetPath);
        }

        Buffer buffer = new ByteArrayBuffer(linkPath.length() + targetPath.length() + Long.SIZE /* some extra fields */, false);
        int version = getVersion();
        if (version < SftpConstants.SFTP_V6) {
            if (!symbolic) {
                throw new UnsupportedOperationException("Hard links are not supported in sftp v" + version);
            }
            buffer.putString(targetPath);
            buffer.putString(linkPath);
            checkCommandStatus(SftpConstants.SSH_FXP_SYMLINK, buffer);
        } else {
            buffer.putString(targetPath);
            buffer.putString(linkPath);
            buffer.putBoolean(symbolic);
            checkCommandStatus(SftpConstants.SSH_FXP_LINK, buffer);
        }
    }

    @Override
    public void lock(Handle handle, long offset, long length, int mask) throws IOException {
        if (!isOpen()) {
            throw new IOException("lock(" + handle + ")[offset=" + offset + ", length=" + length + ", mask=0x" + Integer.toHexString(mask) + "] client is closed");
        }

        if (log.isDebugEnabled()) {
            log.debug("lock({})[{}] offset={}, length={}, mask=0x{}",
                      getClientSession(), handle, offset, length, Integer.toHexString(mask));
        }

        byte[] id = ValidateUtils.checkNotNull(handle, "No handle").getIdentifier();
        Buffer buffer = new ByteArrayBuffer(id.length + Long.SIZE /* a bit extra */, false);
        buffer.putBytes(id);
        buffer.putLong(offset);
        buffer.putLong(length);
        buffer.putInt(mask);
        checkCommandStatus(SftpConstants.SSH_FXP_BLOCK, buffer);
    }

    @Override
    public void unlock(Handle handle, long offset, long length) throws IOException {
        if (!isOpen()) {
            throw new IOException("unlock" + handle + ")[offset=" + offset + ", length=" + length + "] client is closed");
        }

        if (log.isDebugEnabled()) {
            log.debug("unlock({})[{}] offset={}, length={}", getClientSession(), handle, offset, length);
        }

        byte[] id = ValidateUtils.checkNotNull(handle, "No handle").getIdentifier();
        Buffer buffer = new ByteArrayBuffer(id.length + Long.SIZE /* a bit extra */, false);
        buffer.putBytes(id);
        buffer.putLong(offset);
        buffer.putLong(length);
        checkCommandStatus(SftpConstants.SSH_FXP_UNBLOCK, buffer);
    }

    @Override
    public Iterable<DirEntry> readDir(final String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("readDir(" + path + ") client is closed");
        }
        return new SftpIterableDirEntry(this, path);
    }

    @Override
    public InputStream read(final String path, final int bufferSize, final Collection<OpenMode> mode) throws IOException {
        if (bufferSize < MIN_READ_BUFFER_SIZE) {
            throw new IllegalArgumentException("Insufficient read buffer size: " + bufferSize + ", min.=" + MIN_READ_BUFFER_SIZE);
        }

        if (!isOpen()) {
            throw new IOException("read(" + path + ")[" + mode + "] size=" + bufferSize + ": client is closed");
        }

        return new SftpInputStreamWithChannel(this, bufferSize, path, mode);
    }

    @Override
    public OutputStream write(final String path, final int bufferSize, final Collection<OpenMode> mode) throws IOException {
        if (bufferSize < MIN_WRITE_BUFFER_SIZE) {
            throw new IllegalArgumentException("Insufficient write buffer size: " + bufferSize + ", min.=" + MIN_WRITE_BUFFER_SIZE);
        }

        if (!isOpen()) {
            throw new IOException("write(" + path + ")[" + mode + "] size=" + bufferSize + ": client is closed");
        }

        return new SftpOutputStreamWithChannel(this, bufferSize, path, mode);
    }
}
