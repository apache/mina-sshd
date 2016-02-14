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
package org.apache.sshd.common.util.net;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * <P>A simple socket address holding the host name and port number. The reason
 * it does not extend {@link InetSocketAddress} is twofold:</P>
 * <OL>
 * <LI><P>
 * The {@link InetSocketAddress} performs a DNS resolution on the
 * provided host name - which we don't want do use until we want to
 * create a connection using this address (thus the {@link #toInetSocketAddress()}
 * call which executes this query
 * </P></LI>
 *
 * <LI><P>
 * If empty host name is provided we replace it with the <I>any</I>
 * address of 0.0.0.0
 * </P></LI>
 * </OL>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshdSocketAddress extends SocketAddress {
    public static final String LOCALHOST_NAME = "localhost";
    public static final String LOCALHOST_IP = "127.0.0.1";
    public static final String IP_ANYADDR = "0.0.0.0";

    // 10.0.0.0 - 10.255.255.255
    public static final String PRIVATE_CLASS_A_PREFIX = "10.";
    // 172.16.0.0 - 172.31.255.255
    public static final String PRIVATE_CLASS_B_PREFIX = "172.";
    // 192.168.0.0 - 192.168.255.255
    public static final String PRIVATE_CLASS_C_PREFIX = "192.168.";
    // 100.64.0.0 - 100.127.255.255
    public static final String CARRIER_GRADE_NAT_PREFIX = "100.";
    // The IPv4 broadcast address
    public static final String BROADCAST_ADDRESS = "255.255.255.255";

    /**
     * A dummy placeholder that can be used instead of {@code null}s
     */
    public static final SshdSocketAddress LOCALHOST_ADDRESS = new SshdSocketAddress(LOCALHOST_IP, 0);

    /**
     * Compares {@link InetAddress}-es according to their {@link InetAddress#getHostAddress()}
     * value case <U>insensitive</U>
     */
    public static final Comparator<InetAddress> BY_HOST_ADDRESS = new Comparator<InetAddress>() {
            @Override
            public int compare(InetAddress a1, InetAddress a2) {
                String n1 = GenericUtils.trimToEmpty(toAddressString(a1));
                String n2 = GenericUtils.trimToEmpty(toAddressString(a2));
                return String.CASE_INSENSITIVE_ORDER.compare(n1, n2);
            }
        };

    private static final long serialVersionUID = 6461645947151952729L;

    private final String hostName;
    private final int port;

    public SshdSocketAddress(int port) {
        this(IP_ANYADDR, port);
    }

    public SshdSocketAddress(String hostName, int port) {
        ValidateUtils.checkNotNull(hostName, "Host name may not be null");
        this.hostName = GenericUtils.isEmpty(hostName) ? IP_ANYADDR : hostName;

        ValidateUtils.checkTrue(port >= 0, "Port must be >= 0: %d", port);
        this.port = port;
    }

    public String getHostName() {
        return hostName;
    }

    public int getPort() {
        return port;
    }

    public InetSocketAddress toInetSocketAddress() {
        return new InetSocketAddress(getHostName(), getPort());
    }

    @Override
    public String toString() {
        return getHostName() + ":" + getPort();
    }

    protected boolean isEquivalent(SshdSocketAddress that) {
        if (that == null) {
            return false;
        } else if (that == this) {
            return true;
        } else {
            return (this.getPort() == that.getPort())
                    && Objects.equals(this.getHostName(), that.getHostName());
        }
    }

    @Override
    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }
        if (getClass() != o.getClass()) {
            return false;
        }
        return isEquivalent((SshdSocketAddress) o);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getHostName()) + getPort();
    }


    /**
     * Returns the first external network address assigned to this
     * machine or null if one is not found.
     * @return Inet4Address associated with an external interface
     * DevNote:  We actually return InetAddress here, as Inet4Addresses are final and cannot be mocked.
     */
    public static InetAddress getFirstExternalNetwork4Address() {
        List<? extends InetAddress> addresses = getExternalNetwork4Addresses();
        return (GenericUtils.size(addresses) > 0) ? addresses.get(0) : null;
    }

    /**
     * @return a {@link List} of local network addresses which are not multicast
     * or localhost sorted according to {@link #BY_HOST_ADDRESS}
     */
    public static List<InetAddress> getExternalNetwork4Addresses() {
        List<InetAddress> addresses = new ArrayList<InetAddress>();
        try {
            for (Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces(); (nets != null) && nets.hasMoreElements();) {
                NetworkInterface netint = nets.nextElement();
                /* TODO - uncomment when 1.5 compatibility no longer required
                if (!netint.isUp()) {
                    continue;    // ignore non-running interfaces
                }
                */

                for (Enumeration<InetAddress> inetAddresses = netint.getInetAddresses(); (inetAddresses != null) && inetAddresses.hasMoreElements();) {
                    InetAddress inetAddress = inetAddresses.nextElement();
                    if (isValidHostAddress(inetAddress)) {
                        addresses.add(inetAddress);
                    }
                }
            }
        } catch (SocketException e) {
            // swallow
        }

        if (GenericUtils.size(addresses) > 1) {
            Collections.sort(addresses, BY_HOST_ADDRESS);
        }

        return addresses;
    }

    /**
     * @param addr The {@link InetAddress} to be verified
     * @return <P><code>true</code> if the address is:</P></BR>
     * <UL>
     *         <LI>Not <code>null</code></LI>
     *         <LI>An {@link Inet4Address}</LI>
     *         <LI>Not link local</LI>
     *         <LI>Not a multicast</LI>
     *         <LI>Not a loopback</LI>
     * </UL>
     * @see InetAddress#isLinkLocalAddress()
     * @see InetAddress#isMulticastAddress()
     * @see InetAddress#isMulticastAddress()
     */
    public static boolean isValidHostAddress(InetAddress addr) {
        if (addr == null) {
            return false;
        }

        if (addr.isLinkLocalAddress()) {
            return false;
        }

        if (addr.isMulticastAddress()) {
            return false;
        }

        if (!(addr instanceof Inet4Address)) {
            return false;
        }

        if (isLoopback(addr)) {
            return false;
        }

        return true;
    }

    /**
     * @param addr The {@link InetAddress} to be considered
     * @return <code>true</code> if the address is a loopback one.
     * <B>Note:</B> if {@link InetAddress#isLoopbackAddress()}
     * returns <code>false</code> the address <U>string</U> is checked
     * @see #toAddressString(InetAddress)
     * @see #isLoopback(String)
     */
    public static boolean isLoopback(InetAddress addr) {
        if (addr == null) {
            return false;
        }

        if (addr.isLoopbackAddress()) {
            return true;
        }

        String ip = toAddressString(addr);
        return isLoopback(ip);
    }

    /**
     * @param ip IP value to be tested
     * @return <code>true</code> if the IP is &quot;localhost&quot; or
     * &quot;127.x.x.x&quot;.
     */
    public static boolean isLoopback(String ip) {
        if (GenericUtils.isEmpty(ip)) {
            return false;
        }

        if (LOCALHOST_NAME.equals(ip) || LOCALHOST_IP.equals(ip)) {
            return true;
        }

        String[] values = GenericUtils.split(ip, '.');
        if (GenericUtils.length(values) != 4) {
            return false;
        }

        for (int index = 0; index < values.length; index++) {
            String val = values[index];
            if (!isValidIPv4AddressComponent(val)) {
                return false;
            }

            if (index == 0) {
                int number = Integer.parseInt(val);
                if (number != 127) {
                    return false;
                }
            }
        }

        return true;
    }

    public static String toAddressString(SocketAddress addr) {
        if (addr == null) {
            return null;
        }

        if (addr instanceof InetSocketAddress) {
            return ((InetSocketAddress) addr).getHostString();
        }

        if (addr instanceof SshdSocketAddress) {
            return ((SshdSocketAddress) addr).getHostName();
        }

        return addr.toString();
    }

    /**
     * <P>Converts a {@code SocketAddress} into an {@link InetSocketAddress} if possible:</P></BR>
     * <UL>
     *      <LI>If already an {@link InetSocketAddress} then cast it as such</LI>
     *      <LI>If an {@code SshdSocketAddress} then invoke {@link #toInetSocketAddress()}</LI>
     *      <LI>Otherwise, throw an exception</LI>
     * </UL>
     *
     * @param remoteAddress The {@link SocketAddress} - ignored if {@code null}
     * @return The {@link InetSocketAddress} instance
     * @throws ClassCastException if argument is not already an {@code InetSocketAddress}
     * or a {@code SshdSocketAddress}
     */
    public static InetSocketAddress toInetSocketAddress(SocketAddress remoteAddress) {
        if (remoteAddress == null) {
            return null;
        } else if (remoteAddress instanceof InetSocketAddress) {
            return (InetSocketAddress) remoteAddress;
        } else if (remoteAddress instanceof SshdSocketAddress) {
            return ((SshdSocketAddress) remoteAddress).toInetSocketAddress();
        } else {
            throw new ClassCastException("Unknown remote address type: " + remoteAddress);
        }
    }

    public static String toAddressString(InetAddress addr) {
        String ip = (addr == null) ? null : addr.toString();
        if (GenericUtils.isEmpty(ip)) {
            return null;
        } else {
            return ip.replaceAll(".*/", "");
        }
    }

    public static final boolean isIPv4Address(String addr) {
        if (GenericUtils.isEmpty(addr)) {
            return false;
        }

        String[] comps = GenericUtils.split(addr, '.');
        if (GenericUtils.length(comps) != 4) {
            return false;
        }

        for (String c : comps) {
            if (!isValidIPv4AddressComponent(c)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Checks if the address is one of the allocated private blocks
     * @param addr The address string
     * @return {@code true} if this is one of the allocated private
     * blocks. <B>Note:</B> it assumes that the address string is
     * indeed an IPv4 address
     * @see #isIPv4Address(String)
     * @see #PRIVATE_CLASS_A_PREFIX
     * @see #PRIVATE_CLASS_B_PREFIX
     * @see #PRIVATE_CLASS_C_PREFIX
     * @see <A HREF="http://en.wikipedia.org/wiki/Private_network#Private_IPv4_address_spaces">Wiki page</A>
     */
    public static final boolean isPrivateIPv4Address(String addr) {
        if (GenericUtils.isEmpty(addr)) {
            return false;
        }

        if (addr.startsWith(PRIVATE_CLASS_A_PREFIX) || addr.startsWith(PRIVATE_CLASS_C_PREFIX)) {
            return true;
        }

        // for 172.x.x.x we need further checks
        if (!addr.startsWith(PRIVATE_CLASS_B_PREFIX)) {
            return false;
        }

        int nextCompPos = addr.indexOf('.', PRIVATE_CLASS_B_PREFIX.length());
        if (nextCompPos <= PRIVATE_CLASS_B_PREFIX.length()) {
            return false;
        }

        String value = addr.substring(PRIVATE_CLASS_B_PREFIX.length(), nextCompPos);
        if (!isValidIPv4AddressComponent(value)) {
            return false;
        }

        int v = Integer.parseInt(value);
        return (v >= 16) && (v <= 31);
    }

    /**
     * @param addr The address to be checked
     * @return {@code true} if the address is in the 100.64.0.0/10 range
     * @see <A HREF="http://tools.ietf.org/html/rfc6598">RFC6598</A>
     */
    public static final boolean isCarrierGradeNatIPv4Address(String addr) {
        if (GenericUtils.isEmpty(addr)) {
            return false;
        }

        if (!addr.startsWith(CARRIER_GRADE_NAT_PREFIX)) {
            return false;
        }

        int nextCompPos = addr.indexOf('.', CARRIER_GRADE_NAT_PREFIX.length());
        if (nextCompPos <= CARRIER_GRADE_NAT_PREFIX.length()) {
            return false;
        }

        String value = addr.substring(CARRIER_GRADE_NAT_PREFIX.length(), nextCompPos);
        if (!isValidIPv4AddressComponent(value)) {
            return false;
        }

        int v = Integer.parseInt(value);
        return (v >= 64) && (v <= 127);
    }

    /**
     * <P>Checks if the provided argument is a valid IPv4 address component:</P></BR>
     * <UL>
     *     <LI>Not {@code null}/empty</LI>
     *     <LI>Has at most 3 <U>digits</U></LI>
     *     <LI>Its value is &le; 255</LI>
     * </UL>
     * @param c The {@link CharSequence} to be validate
     * @return {@code true} if valid IPv4 address component
     */
    public static final boolean isValidIPv4AddressComponent(CharSequence c) {
        if (GenericUtils.isEmpty(c) || (c.length() > 3)) {
            return false;
        }

        char ch = c.charAt(0);
        if ((ch < '0') || (ch > '9')) {
            return false;
        }

        if (!NumberUtils.isIntegerNumber(c)) {
            return false;
        }

        int v = Integer.parseInt(c.toString());
        return (v >= 0) && (v <= 255);
    }
}
