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
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.sftp.SftpModuleProperties;
import org.apache.sshd.sftp.client.FullAccessSftpClient;
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
public abstract class AbstractSftpClient extends AbstractSubsystemClient implements FullAccessSftpClient {
    public static final int INIT_COMMAND_SIZE = Byte.BYTES /* command */ + Integer.BYTES /* version */;

    private final Attributes fileOpenAttributes = new Attributes();
    private final AtomicReference<Map<String, Object>> parsedExtensionsHolder = new AtomicReference<>(null);

    protected AbstractSftpClient() {
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
     * Sends the specified command, waits for the response and then invokes {@link #checkResponseStatus(int, Buffer)}
     *
     * @param  cmd         The command to send
     * @param  request     The request {@link Buffer}
     * @throws IOException If failed to send, receive or check the returned status
     * @see                #send(int, Buffer)
     * @see                #receive(int)
     * @see                #checkResponseStatus(int, Buffer)
     */
    protected void checkCommandStatus(int cmd, Buffer request) throws IOException {
        int reqId = send(cmd, request);
        Buffer response = receive(reqId);
        checkResponseStatus(cmd, response);
    }

    /**
     * Checks if the incoming response is an {@code SSH_FXP_STATUS} one, and if so whether the substatus is
     * {@code SSH_FX_OK}.
     *
     * @param  cmd         The sent command opcode
     * @param  buffer      The received response {@link Buffer}
     * @throws IOException If response does not carry a status or carries a bad status code
     * @see                #checkResponseStatus(int, int, int, String, String)
     */
    protected void checkResponseStatus(int cmd, Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        validateIncomingResponse(cmd, id, type, length, buffer);

        if (type == SftpConstants.SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            checkResponseStatus(cmd, id, substatus, msg, lang);
        } else {
            IOException err = handleUnexpectedPacket(cmd, SftpConstants.SSH_FXP_STATUS, id, type, length, buffer);
            if (err != null) {
                throw err;
            }
        }
    }

    /**
     * @param  cmd         The sent command opcode
     * @param  id          The request id
     * @param  substatus   The sub-status value
     * @param  msg         The message
     * @param  lang        The language
     * @throws IOException if the sub-status is not {@code SSH_FX_OK}
     * @see                #throwStatusException(int, int, int, String, String)
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
     * @param  cmd         Command to be sent
     * @param  request     The {@link Buffer} containing the request
     * @return             The received handle identifier
     * @throws IOException If failed to send/receive or process the response
     * @see                #send(int, Buffer)
     * @see                #receive(int)
     * @see                #checkHandleResponse(int, Buffer)
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
        validateIncomingResponse(cmd, id, type, length, buffer);

        if (type == SftpConstants.SSH_FXP_HANDLE) {
            return ValidateUtils.checkNotNullAndNotEmpty(buffer.getBytes(), "Null/empty handle in buffer",
                    GenericUtils.EMPTY_OBJECT_ARRAY);
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
        IOException err = handleUnexpectedPacket(cmd, SftpConstants.SSH_FXP_HANDLE, id, type, length, buffer);
        if (err != null) {
            throw err;
        }

        throw new SshException(
                "No handling for unexpected handle packet id=" + id
                               + ", type=" + SftpConstants.getCommandMessageName(type) + ", length=" + length);
    }

    /**
     * @param  cmd         Command to be sent
     * @param  request     Request {@link Buffer}
     * @return             The decoded response {@code Attributes}
     * @throws IOException If failed to send/receive or process the response
     * @see                #send(int, Buffer)
     * @see                #receive(int)
     * @see                #checkAttributesResponse(int, Buffer)
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
        validateIncomingResponse(cmd, id, type, length, buffer);

        if (type == SftpConstants.SSH_FXP_ATTRS) {
            return readAttributes(cmd, buffer, new AtomicInteger(0));
        }

        if (type == SftpConstants.SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (log.isTraceEnabled()) {
                log.trace("checkAttributesResponse({})[id={}] {} - status: {} [{}] {}",
                        getClientChannel(), id, SftpConstants.getCommandMessageName(cmd),
                        SftpConstants.getStatusName(substatus), lang, msg);
            }
            throwStatusException(cmd, id, substatus, msg, lang);
        }

        return handleUnexpectedAttributesPacket(cmd, id, type, length, buffer);
    }

    protected Attributes handleUnexpectedAttributesPacket(int cmd, int id, int type, int length, Buffer buffer)
            throws IOException {
        IOException err = handleUnexpectedPacket(cmd, SftpConstants.SSH_FXP_ATTRS, id, type, length, buffer);
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
     * @see                #checkOneNameResponse(int, Buffer)
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
        validateIncomingResponse(cmd, id, type, length, buffer);

        if (type == SftpConstants.SSH_FXP_NAME) {
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

            Attributes attrs = readAttributes(cmd, buffer, nameIndex);
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
                    String untranslated = getReferencedName(cmd, buffer, nameIndex.getAndIncrement()); // TODO: handle
                                                                                                      // untranslated-name
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

    protected <B extends Buffer> B writeAttributes(int cmd, B buffer, Attributes attributes) throws IOException {
        int version = getVersion();
        int flagsMask = 0;
        Collection<Attribute> flags = Objects.requireNonNull(attributes, "No attributes").getFlags();
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
                    default: // do nothing
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
                buffer = SftpHelper.writeTime(buffer, version, flagsMask, attributes.getAccessTime());
                buffer = SftpHelper.writeTime(buffer, version, flagsMask, attributes.getModifyTime());
            }
        } else if (version >= SftpConstants.SFTP_V4) {
            for (Attribute a : flags) {
                switch (a) {
                    case Size:
                        flagsMask |= SftpConstants.SSH_FILEXFER_ATTR_SIZE;
                        break;
                    case OwnerGroup: {
                        /*
                         * According to
                         * https://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-13.txt
                         * section 7.5
                         *
                         * If either the owner or group field is zero length, the field should be considered absent, and
                         * no change should be made to that specific field during a modification operation.
                         */
                        String owner = attributes.getOwner();
                        String group = attributes.getGroup();
                        if (GenericUtils.isNotEmpty(owner) && GenericUtils.isNotEmpty(group)) {
                            flagsMask |= SftpConstants.SSH_FILEXFER_ATTR_OWNERGROUP;
                        }
                        break;
                    }
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
                    default: // do nothing
                }
            }
            buffer.putInt(flagsMask);
            buffer.putByte((byte) attributes.getType());
            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_SIZE) != 0) {
                buffer.putLong(attributes.getSize());
            }
            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_OWNERGROUP) != 0) {
                String owner = attributes.getOwner();
                buffer.putString(owner);

                String group = attributes.getGroup();
                buffer.putString(group);
            }
            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
                buffer.putInt(attributes.getPermissions());
            }
            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_ACCESSTIME) != 0) {
                buffer = SftpHelper.writeTime(buffer, version, flagsMask, attributes.getAccessTime());
            }
            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_CREATETIME) != 0) {
                buffer = SftpHelper.writeTime(buffer, version, flagsMask, attributes.getCreateTime());
            }
            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_MODIFYTIME) != 0) {
                buffer = SftpHelper.writeTime(buffer, version, flagsMask, attributes.getModifyTime());
            }
            if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_ACL) != 0) {
                buffer = SftpHelper.writeACLs(buffer, version, attributes.getAcl());
            }

            // TODO: for v5 ? 6? add CTIME (see https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#page-16 - v6)
        } else {
            throw new UnsupportedOperationException("writeAttributes(" + attributes + ") unsupported version: " + version);
        }

        if ((flagsMask & SftpConstants.SSH_FILEXFER_ATTR_EXTENDED) != 0) {
            buffer = SftpHelper.writeExtensions(buffer, attributes.getExtensions());
        }

        return buffer;
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
            throw new UnsupportedOperationException(
                    "rename(" + oldPath + " => " + newPath + ")"
                                                    + " - copy options can not be used with this SFTP version: " + options);
        }
        checkCommandStatus(SftpConstants.SSH_FXP_RENAME, buffer);
    }

    @Override
    public int read(Handle handle, long fileOffset, byte[] dst, int dstOffset, int len, AtomicReference<Boolean> eofSignalled)
            throws IOException {
        if (eofSignalled != null) {
            eofSignalled.set(null);
        }
        if (!isOpen()) {
            throw new IOException("read(" + handle + "/" + fileOffset + ")[" + dstOffset + "/" + len + "] client is closed");
        }

        byte[] id = Objects.requireNonNull(handle, "No handle").getIdentifier();
        Buffer buffer = new ByteArrayBuffer(id.length + Long.SIZE /* some extra fields */, false);
        buffer.putBytes(id);
        buffer.putLong(fileOffset);
        buffer.putInt(len);
        return checkData(SftpConstants.SSH_FXP_READ, buffer, dstOffset, dst, eofSignalled);
    }

    protected int checkData(
            int cmd, Buffer request, int dstOffset, byte[] dst, AtomicReference<Boolean> eofSignalled)
            throws IOException {
        if (eofSignalled != null) {
            eofSignalled.set(null);
        }
        int reqId = send(cmd, request);
        Buffer response = receive(reqId);
        return checkDataResponse(cmd, response, dstOffset, dst, eofSignalled);
    }

    protected int checkDataResponse(
            int cmd, Buffer buffer, int dstoff, byte[] dst, AtomicReference<Boolean> eofSignalled)
            throws IOException {
        if (eofSignalled != null) {
            eofSignalled.set(null);
        }

        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        validateIncomingResponse(cmd, id, type, length, buffer);

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
        if ((fileOffset < 0L) || (srcOffset < 0) || (len < 0)) {
            throw new IllegalArgumentException(
                    "write(" + handle + ") please ensure all parameters "
                                               + " are non-negative values: file-offset=" + fileOffset
                                               + ", src-offset=" + srcOffset + ", len=" + len);
        }
        if ((srcOffset + len) > src.length) {
            throw new IllegalArgumentException(
                    "write(" + handle + ")"
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
            log.debug("mkdir({}) {}", getClientChannel(), path);
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE /* some extra fields */, false);
        buffer = putReferencedName(SftpConstants.SSH_FXP_MKDIR, buffer, path, 0);
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
            log.debug("rmdir({}) {}", getClientChannel(), path);
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

        int cmdId = send(SftpConstants.SSH_FXP_READDIR, buffer);
        Buffer response = receive(cmdId);
        return checkDirResponse(SftpConstants.SSH_FXP_READDIR, response, eolIndicator);
    }

    protected List<DirEntry> checkDirResponse(int cmd, Buffer buffer, AtomicReference<Boolean> eolIndicator)
            throws IOException {
        if (eolIndicator != null) {
            eolIndicator.set(null); // assume unknown
        }

        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        validateIncomingResponse(cmd, id, type, length, buffer);

        boolean traceEnabled = log.isTraceEnabled();
        if (type == SftpConstants.SSH_FXP_NAME) {
            ClientChannel channel = getClientChannel();
            int count = buffer.getInt();
            int version = getVersion();
            // Protect against malicious or corrupted packets
            if ((count < 0) || (count > SshConstants.SSH_REQUIRED_PAYLOAD_PACKET_LENGTH_SUPPORT)) {
                log.error("checkDirResponse({})[id={}] illogical dir entries count: {}", channel, id, count);
                throw new SshException("Illogical dir entries count: " + count);
            }

            boolean debugEnabled = log.isDebugEnabled();
            if (debugEnabled) {
                log.debug("checkDirResponse({})[id={}] reading {} entries", channel, id, count);
            }

            List<DirEntry> entries = new ArrayList<>(count);
            AtomicInteger nameIndex = new AtomicInteger(0);
            for (int index = 1; index <= count; index++) {
                String name = getReferencedName(cmd, buffer, nameIndex.getAndIncrement());
                String longName = null;
                if (version == SftpConstants.SFTP_V3) {
                    longName = getReferencedName(cmd, buffer, nameIndex.getAndIncrement());
                }

                Attributes attrs = readAttributes(cmd, buffer, nameIndex);
                if (traceEnabled) {
                    log.trace("checkDirResponse({})[id={}][{}/{}] ({})[{}]: {}",
                            channel, id, index, count, name, longName, attrs);
                }

                entries.add(new DirEntry(name, longName, attrs));
            }

            Boolean indicator = SftpHelper.getEndOfListIndicatorValue(buffer, version);
            if (eolIndicator != null) {
                eolIndicator.set(indicator);
            }

            if (debugEnabled) {
                log.debug("checkDirResponse({})[id={}] read count={}, eol={}",
                        channel, id, entries.size(), indicator);
            }
            return entries;
        }

        if (type == SftpConstants.SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (traceEnabled) {
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

    protected void validateIncomingResponse(
            int cmd, int id, int type, int length, Buffer buffer)
            throws IOException {
        int remaining = buffer.available();
        if ((length < 0) || (length > (remaining + 5 /* type + id */))) {
            throw new SshException(
                    "Bad length (" + length + ") for remaining data (" + remaining + ")"
                                   + " in response to " + SftpConstants.getCommandMessageName(cmd)
                                   + ": type=" + SftpConstants.getCommandMessageName(type) + ", id=" + id);
        }
    }

    protected List<DirEntry> handleUnknownDirListingPacket(
            int cmd, int id, int type, int length, Buffer buffer)
            throws IOException {
        IOException err = handleUnexpectedPacket(cmd, SftpConstants.SSH_FXP_NAME, id, type, length, buffer);
        if (err != null) {
            throw err;
        }
        return Collections.emptyList();
    }

    /**
     * @param  cmd         The initial command sent
     * @param  expected    The expected packet type
     * @param  id          The reported identifier
     * @param  type        The reported SFTP response type
     * @param  length      The packet length
     * @param  buffer      The {@link Buffer} after reading from it whatever data led to this call
     * @return             The exception to throw - if {@code null} then implementor assumed to handle the exception
     *                     internal. Otherwise, the exception is re-thrown
     * @throws IOException If failed to handle the exception internally
     */
    protected IOException handleUnexpectedPacket(
            int cmd, int expected, int id, int type, int length, Buffer buffer)
            throws IOException {
        return new SshException(
                "Unexpected SFTP packet received while awaiting " + SftpConstants.getCommandMessageName(expected)
                                + " response to " + SftpConstants.getCommandMessageName(cmd)
                                + ": type=" + SftpConstants.getCommandMessageName(type) + ", id=" + id + ", length=" + length);
    }

    @Override
    public String canonicalPath(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("canonicalPath(" + path + ") client is closed");
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE, false);
        buffer = putReferencedName(SftpConstants.SSH_FXP_REALPATH, buffer, path, 0);
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
        checkCommandStatus(SftpConstants.SSH_FXP_FSETSTAT, buffer);
    }

    @Override
    public String readLink(String path) throws IOException {
        if (!isOpen()) {
            throw new IOException("readLink(" + path + ") client is closed");
        }

        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE /* some extra fields */, false);
        buffer = putReferencedName(SftpConstants.SSH_FXP_READLINK, buffer, path, 0);
        return checkOneName(SftpConstants.SSH_FXP_READLINK, buffer);
    }

    @Override
    public void link(String linkPath, String targetPath, boolean symbolic) throws IOException {
        if (!isOpen()) {
            throw new IOException("link(" + linkPath + " => " + targetPath + ")[symbolic=" + symbolic + "] client is closed");
        }

        if (log.isDebugEnabled()) {
            log.debug("link({})[symbolic={}] {} => {}", getClientChannel(), symbolic, linkPath, targetPath);
        }

        Buffer buffer = new ByteArrayBuffer(linkPath.length() + targetPath.length() + Long.SIZE /* some extra fields */, false);
        int version = getVersion();
        if (version < SftpConstants.SFTP_V6) {
            if (!symbolic) {
                throw new UnsupportedOperationException("Hard links are not supported in sftp v" + version);
            }
            buffer = putReferencedName(SftpConstants.SSH_FXP_SYMLINK, buffer, targetPath, 0);
            buffer = putReferencedName(SftpConstants.SSH_FXP_SYMLINK, buffer, linkPath, 1);

            checkCommandStatus(SftpConstants.SSH_FXP_SYMLINK, buffer);
        } else {
            buffer = putReferencedName(SftpConstants.SSH_FXP_SYMLINK, buffer, targetPath, 0);
            buffer = putReferencedName(SftpConstants.SSH_FXP_SYMLINK, buffer, linkPath, 1);
            buffer.putBoolean(symbolic);

            checkCommandStatus(SftpConstants.SSH_FXP_LINK, buffer);
        }
    }

    @Override
    public void lock(Handle handle, long offset, long length, int mask) throws IOException {
        if (!isOpen()) {
            throw new IOException(
                    "lock(" + handle + ")[offset=" + offset + ", length=" + length + ", mask=0x" + Integer.toHexString(mask)
                                  + "] client is closed");
        }

        if (log.isDebugEnabled()) {
            log.debug("lock({})[{}] offset={}, length={}, mask=0x{}",
                    getClientChannel(), handle, offset, length, Integer.toHexString(mask));
        }

        byte[] id = Objects.requireNonNull(handle, "No handle").getIdentifier();
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
            log.debug("unlock({})[{}] offset={}, length={}", getClientChannel(), handle, offset, length);
        }

        byte[] id = Objects.requireNonNull(handle, "No handle").getIdentifier();
        Buffer buffer = new ByteArrayBuffer(id.length + Long.SIZE /* a bit extra */, false);
        buffer.putBytes(id);
        buffer.putLong(offset);
        buffer.putLong(length);
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
        if (bufferSize < MIN_WRITE_BUFFER_SIZE) {
            throw new IllegalArgumentException(
                    "Insufficient read buffer size: " + bufferSize + ", min.="
                                               + MIN_READ_BUFFER_SIZE);
        }

        if (!isOpen()) {
            throw new IOException("write(" + path + ")[" + mode + "] size=" + bufferSize + ": client is closed");
        }

        return new SftpInputStreamAsync(this, bufferSize, path, mode);
    }

    @Override
    public InputStream read(String path, Collection<OpenMode> mode) throws IOException {
        int packetSize = (int) getChannel().getRemoteWindow().getPacketSize();
        return read(path, packetSize, mode);
    }

    @Override
    public OutputStream write(String path, int bufferSize, Collection<OpenMode> mode) throws IOException {
        if (bufferSize <= 0) {
            bufferSize = getWriteBufferSize();
        }
        if (bufferSize < MIN_WRITE_BUFFER_SIZE) {
            throw new IllegalArgumentException(
                    "Insufficient write buffer size: " + bufferSize + ", min.="
                                               + MIN_WRITE_BUFFER_SIZE);
        }

        if (!isOpen()) {
            throw new IOException("write(" + path + ")[" + mode + "] size=" + bufferSize + ": client is closed");
        }

        return new SftpOutputStreamAsync(this, bufferSize, path, mode);
    }

    @Override
    public OutputStream write(String path, Collection<OpenMode> mode) throws IOException {
        int packetSize = (int) getChannel().getRemoteWindow().getPacketSize();
        return write(path, packetSize, mode);
    }

    protected int getReadBufferSize() {
        return (int) getClientChannel().getLocalWindow().getPacketSize() - 13;
    }

    protected int getWriteBufferSize() {
        return (int) getClientChannel().getLocalWindow().getPacketSize() - 13;
    }

}
