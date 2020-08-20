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
package org.apache.sshd.scp.client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collection;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionHolder;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.scp.common.ScpHelper;
import org.apache.sshd.scp.common.helpers.ScpTimestampCommandDetails;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ScpClient extends SessionHolder<ClientSession>, ClientSessionHolder {
    enum Option {
        Recursive("-r"),
        PreserveAttributes("-p"),
        TargetIsDirectory("-d"),
        ;

        private final String optionValue;

        Option(String optionValue) {
            this.optionValue = optionValue;
        }

        /**
         * @return The option value to use in the issued SCP command
         */
        public String getOptionValue() {
            return optionValue;
        }
    }

    @Override
    default ClientSession getSession() {
        return getClientSession();
    }

    default void download(String remote, String local, Option... options) throws IOException {
        download(remote, local, GenericUtils.of(options));
    }

    void download(String remote, String local, Collection<Option> options) throws IOException;

    default void download(String remote, Path local, Option... options) throws IOException {
        download(remote, local, GenericUtils.of(options));
    }

    void download(String remote, Path local, Collection<Option> options) throws IOException;

    // NOTE: the remote location MUST be a file or an exception is generated
    void download(String remote, OutputStream local) throws IOException;

    default byte[] downloadBytes(String remote) throws IOException {
        try (ByteArrayOutputStream local = new ByteArrayOutputStream()) {
            download(remote, local);
            return local.toByteArray();
        }
    }

    default void download(String[] remote, String local, Option... options) throws IOException {
        download(remote, local, GenericUtils.of(options));
    }

    default void download(String[] remote, Path local, Option... options) throws IOException {
        download(remote, local, GenericUtils.of(options));
    }

    void download(String[] remote, String local, Collection<Option> options) throws IOException;

    void download(String[] remote, Path local, Collection<Option> options) throws IOException;

    default void upload(String local, String remote, Option... options) throws IOException {
        upload(local, remote, GenericUtils.of(options));
    }

    default void upload(String local, String remote, Collection<Option> options) throws IOException {
        upload(new String[] { ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s", local) }, remote,
                options);
    }

    default void upload(Path local, String remote, Option... options) throws IOException {
        upload(local, remote, GenericUtils.of(options));
    }

    default void upload(Path local, String remote, Collection<Option> options) throws IOException {
        upload(new Path[] { ValidateUtils.checkNotNull(local, "Invalid local argument: %s", local) }, remote,
                GenericUtils.of(options));
    }

    default void upload(String[] local, String remote, Option... options) throws IOException {
        upload(local, remote, GenericUtils.of(options));
    }

    void upload(String[] local, String remote, Collection<Option> options) throws IOException;

    default void upload(Path[] local, String remote, Option... options) throws IOException {
        upload(local, remote, GenericUtils.of(options));
    }

    void upload(Path[] local, String remote, Collection<Option> options) throws IOException;

    // NOTE: due to SCP command limitations, the amount of data to be uploaded must be known a-priori
    // To upload a dynamic amount of data use SFTP
    default void upload(byte[] data, String remote, Collection<PosixFilePermission> perms, ScpTimestampCommandDetails time)
            throws IOException {
        upload(data, 0, data.length, remote, perms, time);
    }

    default void upload(
            byte[] data, int offset, int len, String remote, Collection<PosixFilePermission> perms,
            ScpTimestampCommandDetails time)
            throws IOException {
        try (InputStream local = new ByteArrayInputStream(data, offset, len)) {
            upload(local, remote, len, perms, time);
        }
    }

    void upload(
            InputStream local, String remote, long size, Collection<PosixFilePermission> perms, ScpTimestampCommandDetails time)
            throws IOException;

    static String createSendCommand(String remote, Collection<Option> options) {
        StringBuilder sb = new StringBuilder(remote.length() + Long.SIZE).append(ScpHelper.SCP_COMMAND_PREFIX);
        appendCommandOption(sb, options, Option.TargetIsDirectory);
        appendCommandOption(sb, options, Option.Recursive);
        appendCommandOption(sb, options, Option.PreserveAttributes);

        sb.append(" -t").append(" --").append(' ').append(remote);
        return sb.toString();
    }

    static String createReceiveCommand(String remote, Collection<Option> options) {
        ValidateUtils.checkNotNullAndNotEmpty(remote, "No remote location specified");
        StringBuilder sb = new StringBuilder(remote.length() + Long.SIZE).append(ScpHelper.SCP_COMMAND_PREFIX);
        appendCommandOption(sb, options, Option.Recursive);
        appendCommandOption(sb, options, Option.PreserveAttributes);

        sb.append(" -f").append(" --").append(' ').append(remote);
        return sb.toString();
    }

    /**
     * Appends the specified option command value if appears in provided options collection
     *
     * @param  sb      The {@link StringBuilder} target
     * @param  options The command options - ignored if {@code null}
     * @param  opt     The required option
     * @return         The updated builder
     */
    static StringBuilder appendCommandOption(StringBuilder sb, Collection<Option> options, Option opt) {
        if (GenericUtils.isNotEmpty(options) && options.contains(opt)) {
            sb.append(' ').append(opt.getOptionValue());
        }

        return sb;
    }
}
