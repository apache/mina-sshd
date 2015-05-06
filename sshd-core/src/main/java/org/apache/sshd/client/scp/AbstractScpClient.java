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

package org.apache.sshd.client.scp;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;

import org.apache.sshd.client.ScpClient;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractScpClient implements ScpClient {
    protected AbstractScpClient() {
        super();
    }

    @Override
    public void download(String remote, String local, Option... options) throws IOException {
        download(remote, local, GenericUtils.isEmpty(options) ? Collections.<Option>emptySet() : GenericUtils.of(options));
    }

    @Override
    public void download(String[] remote, String local, Option... options) throws IOException {
        download(remote, local, GenericUtils.isEmpty(options) ? Collections.<Option>emptySet() : GenericUtils.of(options));
    }

    @Override
    public void download(String[] remote, String local, Collection<Option> options) throws IOException {
        local = ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s", local);
        remote = ValidateUtils.checkNotNullAndNotEmpty(remote, "Invalid argument remote: %s", (Object) remote);

        if (remote.length > 1) {
            options = addTargetIsDirectory(options);
        }

        for (String r : remote) {
            download(r, local, options);
        }
    }

    @Override
    public void download(String[] remote, Path local, Option... options) throws IOException {
        download(remote, local, GenericUtils.isEmpty(options) ? Collections.<Option>emptySet() : GenericUtils.of(options));
    }

    @Override
    public void download(String[] remote, Path local, Collection<Option> options) throws IOException {
        remote = ValidateUtils.checkNotNullAndNotEmpty(remote, "Invalid argument remote: %s", (Object) remote);

        if (remote.length > 1) {
            options = addTargetIsDirectory(options);
        }

        for (String r : remote) {
            download(r, local, options);
        }
    }

    @Override
    public void download(String remote, Path local, Option... options) throws IOException {
        download(remote, local, GenericUtils.isEmpty(options) ? Collections.<Option>emptySet() : GenericUtils.of(options));
    }

    @Override
    public void upload(String local, String remote, Option... options) throws IOException {
        upload(local, remote, GenericUtils.isEmpty(options) ? Collections.<Option>emptySet() : GenericUtils.of(options));
    }

    @Override
    public void upload(String local, String remote, Collection<Option> options) throws IOException {
        upload(new String[] { ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s", local) }, remote, options);
    }

    @Override
    public void upload(String[] local, String remote, Option... options) throws IOException {
        upload(local, remote, GenericUtils.isEmpty(options) ? Collections.<Option>emptySet() : GenericUtils.of(options));
    }

    @Override
    public void upload(Path local, String remote, Option... options) throws IOException {
        upload(local, remote, GenericUtils.isEmpty(options) ? Collections.<Option>emptySet() : GenericUtils.of(options));
    }
    
    @Override
    public void upload(Path local, String remote, Collection<Option> options) throws IOException {
        upload(new Path[] { ValidateUtils.checkNotNull(local, "Invalid local argument: %s", local) }, remote, GenericUtils.isEmpty(options) ? Collections.<Option>emptySet() : GenericUtils.of(options));
    }

    @Override
    public void upload(Path[] local, String remote, Option... options) throws IOException {
        upload(local, remote, GenericUtils.isEmpty(options) ? Collections.<Option>emptySet() : GenericUtils.of(options));
    }

    protected Collection<Option> addTargetIsDirectory(Collection<Option> options) {
        if (GenericUtils.isEmpty(options) || (!options.contains(Option.TargetIsDirectory))) {
            // create a copy in case the original collection is un-modifiable
            options = GenericUtils.isEmpty(options) ? EnumSet.noneOf(Option.class) : GenericUtils.of(options);
            options.add(Option.TargetIsDirectory);
        }
        
        return options;
    }
}
