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
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * <P>
 * A simple socket address holding the host name and port number. The reason it does not extend
 * {@link InetSocketAddress} is twofold:
 * </P>
 * <OL>
 * <LI>
 * <P>
 * The {@link InetSocketAddress} performs a DNS resolution on the provided host name - which we don't want do use until
 * we want to create a connection using this address (thus the {@link #toInetSocketAddress()} call which executes this
 * query
 * </P>
 * </LI>
 *
 * <LI>
 * <P>
 * If empty host name is provided we replace it with the <I>any</I> address of 0.0.0.0
 * </P>
 * </LI>
 * </OL>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshdSocketAddress extends SocketAddress {
    public static final String LOCALHOST_NAME = "localhost";
    public static final String LOCALHOST_IPV4 = "127.0.0.1";
    public static final String IPV4_ANYADDR = "0.0.0.0";

    public static final Set<String> WELL_KNOWN_IPV4_ADDRESSES = Collections.unmodifiableSet(
            new LinkedHashSet<>(
                    Arrays.asList(LOCALHOST_IPV4, IPV4_ANYADDR)));

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

    /** Max. number of hex groups (separated by &quot;:&quot;) in an IPV6 address */
    public static final int IPV6_MAX_HEX_GROUPS = 8;

    /** Max. hex digits in each IPv6 group */
    public static final int IPV6_MAX_HEX_DIGITS_PER_GROUP = 4;

    public static final String IPV6_LONG_ANY_ADDRESS = "0:0:0:0:0:0:0:0";
    public static final String IPV6_SHORT_ANY_ADDRESS = "::";

    public static final String IPV6_LONG_LOCALHOST = "0:0:0:0:0:0:0:1";
    public static final String IPV6_SHORT_LOCALHOST = "::1";

    public static final Set<String> WELL_KNOWN_IPV6_ADDRESSES = Collections.unmodifiableSet(
            new LinkedHashSet<>(
                    Arrays.asList(
                            IPV6_LONG_LOCALHOST, IPV6_SHORT_LOCALHOST,
                            IPV6_LONG_ANY_ADDRESS, IPV6_SHORT_ANY_ADDRESS)));

    /**
     * A dummy placeholder that can be used instead of {@code null}s
     */
    public static final SshdSocketAddress LOCALHOST_ADDRESS = new SshdSocketAddress(LOCALHOST_IPV4, 0);

    /**
     * Compares {@link InetAddress}-es according to their {@link InetAddress#getHostAddress()} value case
     * <U>insensitive</U>
     *
     * @see #toAddressString(InetAddress)
     */
    public static final Comparator<InetAddress> BY_HOST_ADDRESS = (a1, a2) -> {
        String n1 = GenericUtils.trimToEmpty(toAddressString(a1));
        String n2 = GenericUtils.trimToEmpty(toAddressString(a2));
        return String.CASE_INSENSITIVE_ORDER.compare(n1, n2);
    };

    /**
     * Compares {@link SocketAddress}-es according to their host case <U>insensitive</U> and if equals, then according
     * to their port value (if any)
     *
     * @see #toAddressString(SocketAddress)
     * @see #toAddressPort(SocketAddress)
     */
    public static final Comparator<SocketAddress> BY_HOST_AND_PORT = (a1, a2) -> {
        String n1 = GenericUtils.trimToEmpty(toAddressString(a1));
        String n2 = GenericUtils.trimToEmpty(toAddressString(a2));
        int nRes = String.CASE_INSENSITIVE_ORDER.compare(n1, n2);
        if (nRes != 0) {
            return nRes;
        }

        int p1 = toAddressPort(a1);
        int p2 = toAddressPort(a2);
        nRes = Integer.compare(p1, p2);
        if (nRes != 0) {
            return nRes;
        }

        return 0;
    };

    private static final long serialVersionUID = 6461645947151952729L;

    private final String hostName;
    private final int port;

    public SshdSocketAddress(int port) {
        this(IPV4_ANYADDR, port);
    }

    public SshdSocketAddress(InetSocketAddress addr) {
        Objects.requireNonNull(addr, "No address provided");

        String host = addr.getHostString();
        hostName = GenericUtils.isEmpty(host) ? IPV4_ANYADDR : host;
        port = addr.getPort();
        ValidateUtils.checkTrue(port >= 0, "Port must be >= 0: %d", port);
    }

    public SshdSocketAddress(String hostName, int port) {
        Objects.requireNonNull(hostName, "Host name may not be null");
        this.hostName = GenericUtils.isEmpty(hostName) ? IPV4_ANYADDR : hostName;

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
                    && isEquivalentHostName(this.getHostName(), that.getHostName(), false);
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
        return GenericUtils.hashCode(getHostName(), Boolean.FALSE) + 31 * Integer.hashCode(getPort());
    }

    /**
     * Returns the first external network address assigned to this machine or null if one is not found.
     *
     * @return Inet4Address associated with an external interface DevNote: We actually return InetAddress here, as
     *         Inet4Addresses are final and cannot be mocked.
     */
    public static InetAddress getFirstExternalNetwork4Address() {
        List<? extends InetAddress> addresses = getExternalNetwork4Addresses();
        return (GenericUtils.size(addresses) > 0) ? addresses.get(0) : null;
    }

    /**
     * @return a {@link List} of local network addresses which are not multicast or localhost sorted according to
     *         {@link #BY_HOST_ADDRESS}
     */
    public static List<InetAddress> getExternalNetwork4Addresses() {
        List<InetAddress> addresses = new ArrayList<>();
        try {
            for (Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
                 (nets != null) && nets.hasMoreElements();) {
                NetworkInterface netint = nets.nextElement();
                /*
                 * TODO - uncomment when 1.5 compatibility no longer required if (!netint.isUp()) { continue; // ignore
                 * non-running interfaces }
                 */

                for (Enumeration<InetAddress> inetAddresses = netint.getInetAddresses();
                     (inetAddresses != null) && inetAddresses.hasMoreElements();) {
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
     * @param  addr The {@link InetAddress} to be verified
     * @return
     *              <P>
     *              <code>true</code> if the address is:
     *              </P>
     *              </BR>
     *              <UL>
     *              <LI>Not {@code null}</LI>
     *              <LI>An {@link Inet4Address}</LI>
     *              <LI>Not link local</LI>
     *              <LI>Not a multicast</LI>
     *              <LI>Not a loopback</LI>
     *              </UL>
     * @see         InetAddress#isLinkLocalAddress()
     * @see         InetAddress#isMulticastAddress()
     * @see         InetAddress#isMulticastAddress()
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
            return false; // TODO add support for IPv6 - see SSHD-746
        }

        return !isLoopback(addr);
    }

    /**
     * @param  addr The {@link InetAddress} to be considered
     * @return      <code>true</code> if the address is a loopback one. <B>Note:</B> if
     *              {@link InetAddress#isLoopbackAddress()} returns <code>false</code> the address <U>string</U> is
     *              checked
     * @see         #toAddressString(InetAddress)
     * @see         #isLoopback(String)
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
     * @param  ip IP value to be tested
     * @return    <code>true</code> if the IP is &quot;localhost&quot; or &quot;127.x.x.x&quot;.
     */
    public static boolean isLoopback(String ip) {
        if (GenericUtils.isEmpty(ip)) {
            return false;
        }

        if (LOCALHOST_NAME.equals(ip)) {
            return true;
        }

        return isIPv4LoopbackAddress(ip) || isIPv6LoopbackAddress(ip);
    }

    public static boolean isIPv4LoopbackAddress(String ip) {
        if (GenericUtils.isEmpty(ip)) {
            return false;
        }

        if (LOCALHOST_IPV4.equals(ip)) {
            return true; // most used
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

    public static boolean isIPv6LoopbackAddress(String ip) {
        // TODO add more patterns - e.g., https://tools.ietf.org/id/draft-smith-v6ops-larger-ipv6-loopback-prefix-04.html
        return IPV6_LONG_LOCALHOST.equals(ip) || IPV6_SHORT_LOCALHOST.equals(ip);
    }

    public static boolean isEquivalentHostName(String h1, String h2, boolean allowWildcard) {
        if (GenericUtils.safeCompare(h1, h2, false) == 0) {
            return true;
        }

        if (allowWildcard) {
            return isWildcardAddress(h1) || isWildcardAddress(h2);
        }

        return false;
    }

    public static boolean isLoopbackAlias(String h1, String h2) {
        return (LOCALHOST_NAME.equals(h1) && isLoopback(h2))
                || (LOCALHOST_NAME.equals(h2) && isLoopback(h1));
    }

    public static boolean isWildcardAddress(String addr) {
        return IPV4_ANYADDR.equalsIgnoreCase(addr)
                || IPV6_LONG_ANY_ADDRESS.equalsIgnoreCase(addr)
                || IPV6_SHORT_ANY_ADDRESS.equalsIgnoreCase(addr);
    }

    public static SshdSocketAddress toSshdSocketAddress(SocketAddress addr) {
        if (addr == null) {
            return null;
        } else if (addr instanceof SshdSocketAddress) {
            return (SshdSocketAddress) addr;
        } else if (addr instanceof InetSocketAddress) {
            InetSocketAddress isockAddress = (InetSocketAddress) addr;
            return new SshdSocketAddress(isockAddress.getHostName(), isockAddress.getPort());
        } else {
            throw new UnsupportedOperationException(
                    "Cannot convert " + addr.getClass().getSimpleName()
                                                    + "=" + addr + " to " + SshdSocketAddress.class.getSimpleName());
        }
    }

    public static String toAddressString(SocketAddress addr) {
        if (addr == null) {
            return null;
        } else if (addr instanceof InetSocketAddress) {
            return ((InetSocketAddress) addr).getHostString();
        } else if (addr instanceof SshdSocketAddress) {
            return ((SshdSocketAddress) addr).getHostName();
        } else {
            return addr.toString();
        }
    }

    /**
     * Attempts to resolve the port value
     *
     * @param  addr The {@link SocketAddress} to examine
     * @return      The associated port value - negative if failed to resolve
     */
    public static int toAddressPort(SocketAddress addr) {
        if (addr instanceof InetSocketAddress) {
            return ((InetSocketAddress) addr).getPort();
        } else if (addr instanceof SshdSocketAddress) {
            return ((SshdSocketAddress) addr).getPort();
        } else {
            return -1;
        }
    }

    /**
     * <P>
     * Converts a {@code SocketAddress} into an {@link InetSocketAddress} if possible:
     * </P>
     * </BR>
     * <UL>
     * <LI>If already an {@link InetSocketAddress} then cast it as such</LI>
     * <LI>If an {@code SshdSocketAddress} then invoke {@link #toInetSocketAddress()}</LI>
     * <LI>Otherwise, throw an exception</LI>
     * </UL>
     *
     * @param  remoteAddress      The {@link SocketAddress} - ignored if {@code null}
     * @return                    The {@link InetSocketAddress} instance
     * @throws ClassCastException if argument is not already an {@code InetSocketAddress} or a {@code SshdSocketAddress}
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

    public static boolean isIPv4Address(String addr) {
        addr = GenericUtils.trimToEmpty(addr);
        if (GenericUtils.isEmpty(addr)) {
            return false;
        }

        if (WELL_KNOWN_IPV4_ADDRESSES.contains(addr)) {
            return true;
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
     *
     * @param  addr The address string
     * @return      {@code true} if this is one of the allocated private blocks. <B>Note:</B> it assumes that the
     *              address string is indeed an IPv4 address
     * @see         #isIPv4Address(String)
     * @see         #PRIVATE_CLASS_A_PREFIX
     * @see         #PRIVATE_CLASS_B_PREFIX
     * @see         #PRIVATE_CLASS_C_PREFIX
     * @see         <A HREF="http://en.wikipedia.org/wiki/Private_network#Private_IPv4_address_spaces">Wiki page</A>
     */
    public static boolean isPrivateIPv4Address(String addr) {
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
     * @param  addr The address to be checked
     * @return      {@code true} if the address is in the 100.64.0.0/10 range
     * @see         <A HREF="http://tools.ietf.org/html/rfc6598">RFC6598</A>
     */
    public static boolean isCarrierGradeNatIPv4Address(String addr) {
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
     * <P>
     * Checks if the provided argument is a valid IPv4 address component:
     * </P>
     * </BR>
     * <UL>
     * <LI>Not {@code null}/empty</LI>
     * <LI>Has at most 3 <U>digits</U></LI>
     * <LI>Its value is &le; 255</LI>
     * </UL>
     *
     * @param  c The {@link CharSequence} to be validate
     * @return   {@code true} if valid IPv4 address component
     */
    public static boolean isValidIPv4AddressComponent(CharSequence c) {
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

    // Based on org.apache.commons.validator.routines.InetAddressValidator#isValidInet6Address
    public static boolean isIPv6Address(String address) {
        address = GenericUtils.trimToEmpty(address);
        if (GenericUtils.isEmpty(address)) {
            return false;
        }

        if (WELL_KNOWN_IPV6_ADDRESSES.contains(address)) {
            return true;
        }

        boolean containsCompressedZeroes = address.contains("::");
        if (containsCompressedZeroes && (address.indexOf("::") != address.lastIndexOf("::"))) {
            return false;
        }

        if (((address.indexOf(':') == 0) && (!address.startsWith("::")))
                || (address.endsWith(":") && (!address.endsWith("::")))) {
            return false;
        }

        String[] splitOctets = GenericUtils.split(address, ':');
        List<String> octetList = new ArrayList<>(Arrays.asList(splitOctets));
        if (containsCompressedZeroes) {
            if (address.endsWith("::")) {
                // String.split() drops ending empty segments
                octetList.add("");
            } else if (address.startsWith("::") && (!octetList.isEmpty())) {
                octetList.remove(0);
            }
        }

        int numOctests = octetList.size();
        if (numOctests > IPV6_MAX_HEX_GROUPS) {
            return false;
        }

        int validOctets = 0;
        int emptyOctets = 0; // consecutive empty chunks
        for (int index = 0; index < numOctests; index++) {
            String octet = octetList.get(index);
            int pos = octet.indexOf('%'); // is it a zone index
            if (pos >= 0) {
                // zone index must come last
                if (index != (numOctests - 1)) {
                    return false;
                }

                octet = (pos > 0) ? octet.substring(0, pos) : "";
            }

            int octetLength = octet.length();
            if (octetLength == 0) {
                emptyOctets++;
                if (emptyOctets > 1) {
                    return false;
                }

                validOctets++;
                continue;
            }

            emptyOctets = 0;

            // Is last chunk an IPv4 address?
            if ((index == (numOctests - 1)) && (octet.indexOf('.') > 0)) {
                if (!isIPv4Address(octet)) {
                    return false;
                }
                validOctets += 2;
                continue;
            }

            if (octetLength > IPV6_MAX_HEX_DIGITS_PER_GROUP) {
                return false;
            }

            int octetInt = 0;
            try {
                octetInt = Integer.parseInt(octet, 16);
            } catch (NumberFormatException e) {
                return false;
            }

            if ((octetInt < 0) || (octetInt > 0x000ffff)) {
                return false;
            }

            validOctets++;
        }

        if ((validOctets > IPV6_MAX_HEX_GROUPS)
                || ((validOctets < IPV6_MAX_HEX_GROUPS) && (!containsCompressedZeroes))) {
            return false;
        }
        return true;
    }

    public static <V> V findByOptionalWildcardAddress(Map<SshdSocketAddress, ? extends V> map, SshdSocketAddress address) {
        Map.Entry<SshdSocketAddress, ? extends V> entry = findMatchingOptionalWildcardEntry(map, address);
        return (entry == null) ? null : entry.getValue();
    }

    public static <V> V removeByOptionalWildcardAddress(Map<SshdSocketAddress, ? extends V> map, SshdSocketAddress address) {
        Map.Entry<SshdSocketAddress, ? extends V> entry = findMatchingOptionalWildcardEntry(map, address);
        return (entry == null) ? null : map.remove(entry.getKey());
    }

    public static <V> Map.Entry<SshdSocketAddress, ? extends V> findMatchingOptionalWildcardEntry(
            Map<SshdSocketAddress, ? extends V> map, SshdSocketAddress address) {
        if (GenericUtils.isEmpty(map) || (address == null)) {
            return null;
        }

        String hostName = address.getHostName();
        Map.Entry<SshdSocketAddress, ? extends V> candidate = null;
        for (Map.Entry<SshdSocketAddress, ? extends V> e : map.entrySet()) {
            SshdSocketAddress a = e.getKey();
            if (a.getPort() != address.getPort()) {
                continue;
            }

            String candidateName = a.getHostName();
            if (hostName.equalsIgnoreCase(candidateName)) {
                return e;   // If found exact match then use it
            }

            if (isEquivalentHostName(hostName, candidateName, true)) {
                if (candidate != null) {
                    throw new IllegalStateException("Multiple candidate matches for " + address + ": " + candidate + ", " + e);
                }
                candidate = e;
            }
        }

        return candidate;
    }
}
