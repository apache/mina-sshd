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

import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.scp.common.ScpFileOpener;
import org.apache.sshd.scp.common.ScpTransferEventListener;
import org.apache.sshd.scp.common.helpers.DefaultScpFileOpener;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractScpClientCreator extends AbstractLoggingBean implements ScpClientCreator {
    private ScpFileOpener opener = DefaultScpFileOpener.INSTANCE;
    private ScpTransferEventListener listener;

    protected AbstractScpClientCreator() {
        this("");
    }

    public AbstractScpClientCreator(String discriminator) {
        super(discriminator);
    }

    @Override
    public ScpFileOpener getScpFileOpener() {
        return opener;
    }

    @Override
    public void setScpFileOpener(ScpFileOpener opener) {
        this.opener = opener;
    }

    @Override
    public ScpTransferEventListener getScpTransferEventListener() {
        return listener;
    }

    @Override
    public void setScpTransferEventListener(ScpTransferEventListener listener) {
        this.listener = listener;
    }
}
