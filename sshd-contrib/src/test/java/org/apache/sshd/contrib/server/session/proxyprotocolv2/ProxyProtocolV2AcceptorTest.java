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

package org.apache.sshd.contrib.server.session.proxyprotocolv2;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.contrib.server.session.proxyprotocol.ProxyProtocolAcceptor;
import org.apache.sshd.contrib.server.session.proxyprotocolv2.exception.ProxyProtocolException;
import org.apache.sshd.server.session.AbstractServerSession;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.type;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Test Suite for Proxy Protocol V2 handling.
 *
 * @author Oodrive - François HERBRETEAU (f.herbreteau@oodrive.com)
 */
@RunWith(MockitoJUnitRunner.class)
public class ProxyProtocolV2AcceptorTest {

    private final ProxyProtocolAcceptor acceptor = new ProxyProtocolV2Acceptor();

    @Mock
    private AbstractServerSession session;

    @Captor
    private ArgumentCaptor<InetSocketAddress> socketAddressArgumentCaptor;

    public ProxyProtocolV2AcceptorTest() {
        // Nothing to do.
    }

    @Test
    public void testHandlingProxyProtocolV1Tcp4() throws Exception {
        // Given
        ByteArrayBuffer buffer = new ByteArrayBuffer("PROXY TCP4 172.19.0.1 172.19.0.3 42272 80\r\n".getBytes());

        // When
        assertTrue(acceptor.acceptServerProxyMetadata(session, buffer));

        // Then
        verify(session).setClientAddress(socketAddressArgumentCaptor.capture());
        assertThat(socketAddressArgumentCaptor.getValue())
                .isNotNull()
                .isInstanceOf(InetSocketAddress.class)
                .asInstanceOf(type(InetSocketAddress.class))
                .extracting(InetSocketAddress::getAddress)
                .asInstanceOf(type(InetAddress.class))
                .extracting(InetAddress::getHostAddress)
                .asString()
                .isEqualTo("172.19.0.1");
        assertThat(buffer.available()).isZero();
        assertThat(buffer.rpos()).isEqualTo(43);
    }

    @Test
    public void testHandlingProxyProtocolV1Tpc6() throws Exception {
        // Given
        ByteArrayBuffer buffer
                = new ByteArrayBuffer("PROXY TCP6 fe80::a00:27ff:fe9f:4016 fe80::a089:a3ff:fe15:e992 42272 80\r\n".getBytes());

        // When
        assertTrue(acceptor.acceptServerProxyMetadata(session, buffer));

        // Then
        verify(session).setClientAddress(socketAddressArgumentCaptor.capture());
        assertThat(socketAddressArgumentCaptor.getValue())
                .isNotNull()
                .isInstanceOf(InetSocketAddress.class)
                .asInstanceOf(type(InetSocketAddress.class))
                .extracting(InetSocketAddress::getAddress)
                .asInstanceOf(type(InetAddress.class))
                .extracting(InetAddress::getHostAddress)
                .asString()
                .isEqualTo("fe80:0:0:0:a00:27ff:fe9f:4016");
        assertThat(buffer.available()).isZero();
        assertThat(buffer.rpos()).isEqualTo(72);
    }

    @Test
    public void testHandlingProxyProtocolV2Tcp4() throws Exception {
        // Given
        ByteArrayBuffer buffer = new ByteArrayBuffer(new byte[] {
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                0x21, 0x11, 0x00, 0x0c, (byte) 0xac, 0x13, 0x00, 0x01, (byte) 0xac, 0x13, 0x00, 0x03,
                (byte) 0xa5, 0x20, 0x00, (byte) 0x50 });
        //When
        assertTrue(acceptor.acceptServerProxyMetadata(session, buffer));

        //Then
        verify(session).setClientAddress(socketAddressArgumentCaptor.capture());
        assertThat(socketAddressArgumentCaptor.getValue())
                .isNotNull()
                .isInstanceOf(InetSocketAddress.class)
                .asInstanceOf(type(InetSocketAddress.class))
                .extracting(InetSocketAddress::getAddress)
                .asInstanceOf(type(InetAddress.class))
                .extracting(InetAddress::getHostAddress)
                .asString()
                .isEqualTo("172.19.0.1");
        assertThat(buffer.available()).isZero();
        assertThat(buffer.rpos()).isEqualTo(28);
    }

    @Test
    public void testHandlingProxyProtocolV2Tcp6() throws Exception {
        // Given
        ByteArrayBuffer buffer = new ByteArrayBuffer(new byte[] {
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                0x21, 0x21, 0x00, 0x24, (byte) 0xfe, (byte) 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
                0x00, 0x27, (byte) 0xff, (byte) 0xfe, (byte) 0x9f, 0x40, 0x16, (byte) 0xfe, (byte) 0x80, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xa0, (byte) 0x89, (byte) 0xa3, (byte) 0xff, (byte) 0xfe,
                0x15, (byte) 0xe9, (byte) 0x92, (byte) 0xa5, 0x20, 0x00, (byte) 0x50 });

        // When
        assertTrue(acceptor.acceptServerProxyMetadata(session, buffer));

        // Then
        verify(session).setClientAddress(socketAddressArgumentCaptor.capture());
        assertThat(socketAddressArgumentCaptor.getValue())
                .isNotNull()
                .isInstanceOf(InetSocketAddress.class)
                .asInstanceOf(type(InetSocketAddress.class))
                .extracting(InetSocketAddress::getAddress)
                .asInstanceOf(type(InetAddress.class))
                .extracting(InetAddress::getHostAddress)
                .asString()
                .isEqualTo("fe80:0:0:0:a00:27ff:fe9f:4016");
        assertThat(buffer.available()).isZero();
        assertThat(buffer.rpos()).isEqualTo(52);
    }

    @Test
    public void testHandlingProxyProtocolV2UnixSocket() throws Exception {
        // Given
        ByteArrayBuffer buffer = new ByteArrayBuffer(new byte[] {
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                0x21, 0x31, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00 });

        //When
        assertTrue(acceptor.acceptServerProxyMetadata(session, buffer));

        //Then
        assertThat(buffer.available()).isZero();
        assertThat(buffer.rpos()).isEqualTo(20);

    }

    @Test
    public void testHandlingProxyProtocolV2Udp4() throws Exception {
        // Given
        ByteArrayBuffer buffer = new ByteArrayBuffer(new byte[] {
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                0x21, 0x12, 0x00, 0x0c, (byte) 0xac, 0x13, 0x00, 0x01, (byte) 0xac, 0x13, 0x00, 0x03,
                (byte) 0xa5, 0x20, 0x00, (byte) 0x50 });

        //When
        assertTrue(acceptor.acceptServerProxyMetadata(session, buffer));

        //Then
        assertThat(buffer.available()).isZero();
        assertThat(buffer.rpos()).isEqualTo(28);

    }

    @Test
    public void testHandlingProxyProtocolV2Udp6() throws Exception {
        // Given
        ByteArrayBuffer buffer = new ByteArrayBuffer(new byte[] {
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                0x21, 0x22, 0x00, 0x24, (byte) 0xfe, (byte) 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
                0x00, 0x27, (byte) 0xff, (byte) 0xfe, (byte) 0x9f, 0x40, 0x16, (byte) 0xfe, (byte) 0x80, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xa0, (byte) 0x89, (byte) 0xa3, (byte) 0xff, (byte) 0xfe,
                0x15, (byte) 0xe9, (byte) 0x92, (byte) 0xa5, 0x20, 0x00, (byte) 0x50 });

        //When
        assertTrue(acceptor.acceptServerProxyMetadata(session, buffer));

        //Then
        assertThat(buffer.available()).isZero();
        assertThat(buffer.rpos()).isEqualTo(52);

    }

    @Test
    public void testHandlingOtherProtocolHeader() throws Exception {
        // Given
        ByteArrayBuffer buffer = new ByteArrayBuffer("SSH-2.0-OpenSSH_9.3".getBytes());

        //When
        assertTrue(acceptor.acceptServerProxyMetadata(session, buffer));

        //Then
        verify(session, never()).setClientAddress(any());
        assertThat(buffer.available()).isEqualTo(19);
        assertThat(buffer.rpos()).isZero();
    }

    @Test
    public void testHandlingProxyProtocolV2WithLocalCommand() throws Exception {
        // Given
        ByteArrayBuffer buffer = new ByteArrayBuffer(new byte[] {
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                0x20, 0x00, 0x00, 0x00 });

        //When
        assertTrue(acceptor.acceptServerProxyMetadata(session, buffer));

        //Then
        verify(session, never()).setClientAddress(any());
        assertThat(buffer.available()).isZero();
        assertThat(buffer.rpos()).isEqualTo(16);
    }

    @Test
    public void testHandlingProxyProtocolV2WithExtendedData() throws Exception {
        // Given
        ByteArrayBuffer buffer = new ByteArrayBuffer(new byte[] {
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                0x20, 0x00, 0x00, 0x07, 0x03, 0x00, 0x04, (byte) 0xa9, (byte) 0xb8, 0x7e, (byte) 0x8f });

        //When
        assertTrue(acceptor.acceptServerProxyMetadata(session, buffer));
        //Then
        verify(session, never()).setClientAddress(any());
        assertThat(buffer.available()).isZero();
        assertThat(buffer.rpos()).isEqualTo(23);

    }

    @Test
    public void testHandlingProxyProtocolV2WithInvalidVersion() {
        // Given
        ByteArrayBuffer buffer = new ByteArrayBuffer(new byte[] {
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                0x31, 0x11, 0x00, 0x0c, (byte) 0xac, 0x13, 0x00, 0x01, (byte) 0xac, 0x13, 0x00, 0x03,
                (byte) 0xa5, 0x20, 0x00, (byte) 0x50 });

        //When
        ProxyProtocolException exception
                = assertThrows(ProxyProtocolException.class, () -> acceptor.acceptServerProxyMetadata(session, buffer));

        //Then
        assertThat(exception).hasMessage("Invalid version 3");
        assertThat(buffer.available()).isEqualTo(15);
        assertThat(buffer.rpos()).isEqualTo(13);
    }

    @Test
    public void testHandlingProxyProtocolV2WithUnassignedCommand() {
        // Given
        ByteArrayBuffer buffer = new ByteArrayBuffer(new byte[] {
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                0x23, 0x00, 0x00, 0x00 });

        //When
        ProxyProtocolException exception
                = assertThrows(ProxyProtocolException.class, () -> acceptor.acceptServerProxyMetadata(session, buffer));

        //Then
        assertThat(exception).hasMessage("Unassigned command 3");
        verify(session, never()).setClientAddress(any());
        assertThat(buffer.available()).isEqualTo(3);
        assertThat(buffer.rpos()).isEqualTo(13);
    }

    @Test
    public void testHandlingProxyProtocolV2WithUnexpectedFamily() {
        // Given
        ByteArrayBuffer buffer = new ByteArrayBuffer(new byte[] {
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                0x21, 0x40, 0x00, 0x00 });

        //When
        ProxyProtocolException exception
                = assertThrows(ProxyProtocolException.class, () -> acceptor.acceptServerProxyMetadata(session, buffer));

        //Then
        assertThat(exception).hasMessage("Unspecified family 4");
        verify(session, never()).setClientAddress(any());
        assertThat(buffer.available()).isEqualTo(2);
        assertThat(buffer.rpos()).isEqualTo(14);
    }

    @Test
    public void testHandlingProxyProtocolV2WithUnexpectedTransport() {
        // Given
        ByteArrayBuffer buffer = new ByteArrayBuffer(new byte[] {
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
                0x21, 0x14, 0x00, 0x00 });

        //When
        ProxyProtocolException exception
                = assertThrows(ProxyProtocolException.class, () -> acceptor.acceptServerProxyMetadata(session, buffer));

        //Then
        assertThat(exception).hasMessage("Unspecified transport 4");
        verify(session, never()).setClientAddress(any());
        assertThat(buffer.available()).isEqualTo(2);
        assertThat(buffer.rpos()).isEqualTo(14);
    }

    @Test
    public void testHandlingProxyProtocolV2WithInvalidSize() throws Exception {
        // Given
        ByteArrayBuffer buffer = new ByteArrayBuffer(new byte[] { 0x00, 0x00, 0x00, 0x00 });

        //When
        assertFalse(acceptor.acceptServerProxyMetadata(session, buffer));

        //Then
        verify(session, never()).setClientAddress(any());
        assertThat(buffer.available()).isEqualTo(4);
        assertThat(buffer.rpos()).isZero();

    }
}
