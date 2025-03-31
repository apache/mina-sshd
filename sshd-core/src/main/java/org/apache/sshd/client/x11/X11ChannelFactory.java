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
package org.apache.sshd.client.x11;

import org.apache.sshd.client.channel.ChannelX11;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.core.CoreModuleProperties;

import java.io.IOException;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class X11ChannelFactory implements ChannelFactory {

    public static final X11ChannelFactory INSTANCE = new X11ChannelFactory();

    public X11ChannelFactory() {
    }

    @Override
    public Channel createChannel(Session session) throws IOException {
        final String host = CoreModuleProperties.X11_BIND_HOST.get(session).orElse(null);
        final Integer port = CoreModuleProperties.X11_BASE_PORT.get(session).orElse(null);
        if (host == null || port == null) {
            return null;
        }
        return new ChannelX11(host, port);
    }

    @Override
    public String getName() {
        return "x11";
    }
}
