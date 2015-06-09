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

package org.apache.sshd.client.session;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.forward.DefaultTcpipForwarderFactory;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.random.JceRandom;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.random.SingletonRandomFactory;
import org.apache.sshd.util.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ClientSessionImplTest extends BaseTestSupport {
    public ClientSessionImplTest() {
        super();
    }

    @Test
    public void testAddRemoveIdentities() throws Exception {
        ClientFactoryManager client = Mockito.mock(ClientFactoryManager.class);
        Mockito.when(client.getTcpipForwarderFactory()).thenReturn(DefaultTcpipForwarderFactory.INSTANCE);
        
        Factory<Random> randomFactory = new SingletonRandomFactory(JceRandom.JceRandomFactory.INSTANCE);
        Mockito.when(client.getRandomFactory()).thenReturn(randomFactory);
        
        List<ServiceFactory> serviceFactories = Arrays.asList(
                    new ClientUserAuthService.Factory(),
                    new ClientConnectionService.Factory()
                );
        Mockito.when(client.getServiceFactories()).thenReturn(serviceFactories);

        try(ClientSession session = new ClientSessionImpl(client, Mockito.mock(IoSession.class)) {
            @Override
            protected void sendClientIdentification() {
                // ignored
            }
            
            @Override
            protected void sendKexInit() throws IOException {
                // ignored
            }

            @Override
            public void close() throws IOException {
                // ignored
            }
        }) {
            {
                String expected = getCurrentTestName();
                assertNull("Unexpected initial password identity", session.removePasswordIdentity(expected));
                session.addPasswordIdentity(expected);
    
                String actual = session.removePasswordIdentity(expected);
                assertSame("Mismatched removed password identity", expected, actual);
                assertNull("Password identity not removed", session.removePasswordIdentity(expected));
            }
            
            {
                KeyPair expected = new KeyPair(Mockito.mock(PublicKey.class), Mockito.mock(PrivateKey.class));
                assertNull("Unexpected initial pubket identity", session.removePublicKeyIdentity(expected));
                session.addPublicKeyIdentity(expected);
                
                KeyPair actual = session.removePublicKeyIdentity(expected);
                assertSame("Mismatched removed pubkey identity", expected, actual);
                assertNull("Pubkey identity not removed", session.removePublicKeyIdentity(expected));
            }
        }
    }
}
