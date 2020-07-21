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

package org.apache.sshd.ldap;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.net.NetworkConnector;

/**
 * Uses the <A HREF="http://docs.oracle.com/javase/7/docs/technotes/guides/jndi/jndi-ldap.html"> LDAP Naming Service
 * Provider for the Java Naming and Directory Interface (JNDI)</A>
 *
 * @param  <C> Type of context being passed to {@link #resolveAttributes(String, String, Object)}
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LdapNetworkConnector<C> extends NetworkConnector {
    public static final String DEFAULT_LDAP_PROTOCOL = "ldap";
    public static final int DEFAULT_LDAP_PORT = 389;

    /**
     * Property used to override the default LDAP context factory class
     */
    public static final String DEFAULT_LDAP_FACTORY_PROPNAME = "javax.naming.ldap.factory";
    /**
     * Default LDAP context factory class - unless overridden via the {@link #DEFAULT_LDAP_FACTORY_PROPNAME} property
     */
    public static final String DEFAULT_LDAP_FACTORY_PROPVAL = "com.sun.jndi.ldap.LdapCtxFactory";
    public static final int DEFAULT_LDAP_SEARCH_SCOPE = SearchControls.SUBTREE_SCOPE;
    public static final long DEFAULT_LDAP_TIME_LIMIT = TimeUnit.SECONDS.toMillis(15L);
    public static final String DEFAULT_LDAP_REFERRAL_MODE = "ignore";
    public static final long DEFAULT_LDAP_COUNT_LIMIT = 1L;
    public static final boolean DEFAULT_LDAP_DEREF_ENABLED = false;
    /**
     * A special value used to indicate that all attributes are required
     */
    public static final String ALL_LDAP_ATTRIBUTES = "*";
    public static final boolean DEFAULT_LDAP_RETURN_OBJVALUE = false;
    public static final boolean DEFAULT_LDAP_ACCUMULATE_MULTIVALUES = false;
    public static final String DEFAULT_LDAP_BIND_DN_PATTERN = "{0}";
    public static final String DEFAULT_LDAP_BIND_PASSWORD_PATTERN = "{1}";
    /**
     * A list of known binary attributes
     * 
     * @see <A HREF="http://docs.oracle.com/javase/jndi/tutorial/ldap/misc/attrs.html">LDAP Attributes</A>
     */
    public static final String DEFAULT_BINARY_ATTRIBUTES
            = "photo,personalSignature,audio,jpegPhoto,javaSerializedData,thumbnailPhoto,thumbnailLogo"
              + ",userPassword,userCertificate,cACertificate,authorityRevocationList,certificateRevocationList"
              + ",crossCertificatePair,x500UniqueIdentifier";

    protected final SearchControls searchControls = new SearchControls();
    protected final Map<String, Object> ldapEnv = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    protected MessageFormat bindDNPattern = new MessageFormat(DEFAULT_LDAP_BIND_DN_PATTERN);
    protected MessageFormat bindPasswordPattern = new MessageFormat(DEFAULT_LDAP_BIND_PASSWORD_PATTERN);
    protected MessageFormat searchFilterPattern;
    protected MessageFormat baseDNPattern;

    private boolean accumulateMultiValues = DEFAULT_LDAP_ACCUMULATE_MULTIVALUES;

    public LdapNetworkConnector() {
        setProtocol(DEFAULT_LDAP_PROTOCOL);
        setPort(DEFAULT_LDAP_PORT);
        setSearchScope(DEFAULT_LDAP_SEARCH_SCOPE);
        setLdapFactory(DEFAULT_LDAP_FACTORY_PROPVAL);
        setTimeLimit(DEFAULT_LDAP_TIME_LIMIT);
        setCountLimit(DEFAULT_LDAP_COUNT_LIMIT);
        setDerefLink(DEFAULT_LDAP_DEREF_ENABLED);
        setReturningObjFlag(DEFAULT_LDAP_RETURN_OBJVALUE);
        setReferralMode(DEFAULT_LDAP_REFERRAL_MODE);
        setBinaryAttributes(DEFAULT_BINARY_ATTRIBUTES);
    }

    @Override
    public void setConnectTimeout(long connectTimeout) {
        // value must fit in an integer
        ValidateUtils.checkTrue((connectTimeout >= Integer.MIN_VALUE) && (connectTimeout <= Integer.MAX_VALUE),
                "Invalid connect timeout: %d", connectTimeout);
        ldapEnv.put("com.sun.jndi.ldap.connect.timeout", Long.toString(connectTimeout));
        super.setConnectTimeout(connectTimeout);
    }

    @Override
    public void setReadTimeout(long readTimeout) {
        // value must fit in an integer
        ValidateUtils.checkTrue((readTimeout >= Integer.MIN_VALUE) && (readTimeout <= Integer.MAX_VALUE),
                "Invalid read timeout: %d", readTimeout);
        super.setReadTimeout(readTimeout);
        ldapEnv.put("com.sun.jndi.ldap.read.timeout", Long.toString(readTimeout));
    }

    public String getLdapFactory() {
        return Objects.toString(ldapEnv.get(Context.INITIAL_CONTEXT_FACTORY), null);
    }

    /**
     * @param factory The LDAP context factory
     */
    public void setLdapFactory(String factory) {
        ldapEnv.put(Context.INITIAL_CONTEXT_FACTORY, ValidateUtils.checkNotNullAndNotEmpty(factory, "No LDAP factory"));
    }

    public String getBaseDN() {
        return baseDNPattern.toPattern();
    }

    /**
     * @param p The base DN pattern - the arguments to the pattern depend on the actual usage
     * @see     MessageFormat#format(String, Object...)
     */
    public void setBaseDN(String p) {
        baseDNPattern = new MessageFormat(ValidateUtils.checkNotNullAndNotEmpty(p, "No base DN pattern"));
    }

    public String getBindDNPattern() {
        return bindDNPattern.toPattern();
    }

    public void setBindDNPattern(String p) {
        bindDNPattern = new MessageFormat(ValidateUtils.checkNotNullAndNotEmpty(p, "No bind DN pattern"));
    }

    public String getBindPasswordPattern() {
        return bindPasswordPattern.toPattern();
    }

    public void setBindPasswordPattern(String p) {
        bindPasswordPattern = new MessageFormat(ValidateUtils.checkNotNullAndNotEmpty(p, "No bind password pattern"));
    }

    public String getSearchFilterPattern() {
        return searchFilterPattern.toPattern();
    }

    public void setSearchFilterPattern(String p) {
        searchFilterPattern = new MessageFormat(ValidateUtils.checkNotNullAndNotEmpty(p, "No seatch filter pattern"));
    }

    /**
     * @return The search scope
     * @see    SearchControls#OBJECT_SCOPE
     * @see    SearchControls#ONELEVEL_SCOPE
     * @see    SearchControls#SUBTREE_SCOPE
     */
    public int getSearchScope() {
        return searchControls.getSearchScope();
    }

    /**
     * @param scope The search scope
     * @see         SearchControls#OBJECT_SCOPE
     * @see         SearchControls#ONELEVEL_SCOPE
     * @see         SearchControls#SUBTREE_SCOPE
     */
    public void setSearchScope(int scope) {
        searchControls.setSearchScope(scope);
    }

    /**
     * @return Time limit (millis) to wait for result - zero means forever
     */
    public long getTimeLimit() {
        return searchControls.getTimeLimit();
    }

    public void setTimeLimit(long limit) {
        ValidateUtils.checkTrue(limit >= 0L, "Negative time limit: %d", limit);
        searchControls.setTimeLimit((int) limit);
    }

    /**
     * @return Maximum number of entries to be returned in a query
     */
    public long getCountLimit() {
        return searchControls.getCountLimit();
    }

    public void setCountLimit(long count) {
        ValidateUtils.checkTrue(count >= 0L, "Bad count limit: %d", count);
        searchControls.setCountLimit(count);
    }

    /**
     * @return {@code true} whether links should be de-referenced
     * @see    SearchControls#getDerefLinkFlag()
     */
    public boolean isDerefLink() {
        return searchControls.getDerefLinkFlag();
    }

    public void setDerefLink(boolean enabled) {
        searchControls.setDerefLinkFlag(enabled);
    }

    /**
     * @return Comma separated list of attributes to retrieve
     */
    public String getRetrievedAttributes() {
        String[] attrs = searchControls.getReturningAttributes();
        if (attrs == null) {
            return "*";
        } else if (attrs.length == 0) {
            return "";
        } else if (attrs.length == 1) {
            return attrs[0];
        } else {
            return GenericUtils.join(attrs, ',');
        }
    }

    /**
     * @param attrs Comma separated list of attributes to retrieve - if {@code null}/empty then no attributes are
     *              retrieved
     * @see         SearchControls#setReturningAttributes(String[])
     */
    public void setRetrievedAttributes(String attrs) {
        if (GenericUtils.isEmpty(attrs)) {
            searchControls.setReturningAttributes(GenericUtils.EMPTY_STRING_ARRAY);
        } else if (ALL_LDAP_ATTRIBUTES.equals(attrs)) {
            searchControls.setReturningAttributes(null);
        } else {
            searchControls.setReturningAttributes(GenericUtils.split(attrs, ','));
        }
    }

    public boolean isAccumulateMultiValues() {
        return accumulateMultiValues;
    }

    public void setAccumulateMultiValues(boolean enabled) {
        accumulateMultiValues = enabled;
    }

    /**
     * @return {@code true} if objects are returned as result of the query
     * @see    SearchControls#getReturningObjFlag()
     */
    public boolean isReturningObjFlag() {
        return searchControls.getReturningObjFlag();
    }

    public void setReturningObjFlag(boolean enabled) {
        searchControls.setReturningObjFlag(enabled);
    }

    /**
     * @return Authentication mode to use: &qout;none&quot;, &quot;simple&quot;, etc.
     * @see    Context#SECURITY_AUTHENTICATION
     */
    public String getAuthenticationMode() {
        return Objects.toString(ldapEnv.get(Context.SECURITY_AUTHENTICATION), null);
    }

    public void setAuthenticationMode(String mode) {
        ldapEnv.put(Context.SECURITY_AUTHENTICATION, Objects.requireNonNull(mode, "No authentication mode"));
    }

    /**
     * @return How referrals encountered by the service provider are to be processed
     * @see    Context#REFERRAL
     */
    public String getReferralMode() {
        return Objects.toString(ldapEnv.get(Context.REFERRAL), null);
    }

    public void setReferralMode(String mode) {
        ldapEnv.put(Context.REFERRAL, ValidateUtils.checkNotNullAndNotEmpty(mode, "No referral mode"));
    }

    /**
     * @return The specified protocol version - non-positive if default provider version used
     */
    public int getProtocolVersion() {
        Object value = ldapEnv.get("java.naming.ldap.version");
        return (value != null) ? ((Number) value).intValue() : -1;
    }

    public void setProtocolVersion(int value) {
        ValidateUtils.checkTrue(value > 0, "Non-positive protocol value: %d", value);
        ldapEnv.put("java.naming.ldap.version", value);
    }

    /**
     * @return Comma separated list of attributes known to be binary so that they are returned as {@code byte[]} value
     *         rather than strings
     */
    public String getBinaryAttributes() {
        return Objects.toString(ldapEnv.get("java.naming.ldap.attributes.binary"), "").replace(' ', ',');
    }

    /**
     * @param value Comma separated list of attributes known to be binary so that they are returned as {@code byte[]}
     *              value rather than strings
     * @see         <A HREF="http://docs.oracle.com/javase/jndi/tutorial/ldap/misc/attrs.html">LDAP Attributes</A>
     */
    public void setBinaryAttributes(String value) {
        value = ValidateUtils.checkNotNullAndNotEmpty(value, "No attributes").replace(',', ' ');
        ldapEnv.put("java.naming.ldap.attributes.binary", value);
    }

    /**
     * @param  username        Username to be used either to access the LDAP or retrieve the user's attributes - may be
     *                         {@code null}/empty if not required for the specific query
     * @param  password        Password Password to be used if necessary - may be {@code null}/empty if not required for
     *                         the specific query
     * @param  queryContext    User specific query context - relevant for derived classes that want to override some of
     *                         query processing methods
     * @return                 A {@link Map} of the retrieved attributes - <B>Note:</B> if
     *                         {@link #isAccumulateMultiValues()} is {@code true} and multiple values are encountered
     *                         for an attribute then a {@link List} of them is mapped as its value
     * @throws NamingException If failed to executed the LDAP query
     * @see                    #queryAttributes(Object, DirContext, Map, String, String)
     */
    public Map<String, Object> resolveAttributes(String username, String password, C queryContext) throws NamingException {
        // create a copy of the original environment so we can change it
        DirContext context = initializeDirContext(queryContext, new HashMap<>(ldapEnv), username, password);
        try {
            return queryAttributes(queryContext, context, context.getEnvironment(), username, password);
        } finally {
            context.close();
        }
    }

    /**
     * @param  queryContext    The user-specific query context
     * @param  context         The initialized {@link DirContext}
     * @param  ldapConfig      The LDAP environment setup
     * @param  username        The username
     * @param  password        The password
     * @return                 A {@link Map} of the retrieved attributes - <B>Note:</B> if
     *                         {@link #isAccumulateMultiValues()} is {@code true} and multiple values are encountered
     *                         for an attribute then a {@link List} of them is mapped as its value
     * @throws NamingException If failed to executed the LDAP query
     */
    protected Map<String, Object> queryAttributes(
            C queryContext, DirContext context, Map<?, ?> ldapConfig, String username, String password)
            throws NamingException {
        String baseDN = resolveBaseDN(queryContext, ldapConfig, username, password);
        String filter = resolveSearchFilter(queryContext, ldapConfig, username, password);
        NamingEnumeration<? extends SearchResult> result
                = context.search(ValidateUtils.checkNotNullAndNotEmpty(baseDN, "No base DN"),
                        ValidateUtils.checkNotNullAndNotEmpty(filter, "No filter"),
                        searchControls);
        try {
            Map<String, Object> attrsMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            String referralMode = Objects.toString(ldapConfig.get(Context.REFERRAL), null);
            for (int index = 0;; index++) {
                if (!result.hasMore()) {
                    break;
                }

                processSearchResult(queryContext, ldapConfig, attrsMap, index, result.next());

                // if not following referrals stop at the 1st result regardless if there are others
                if ("ignore".equals(referralMode)) {
                    break;
                }
            }

            return attrsMap;
        } finally {
            result.close();
        }
    }

    protected DirContext initializeDirContext(C queryContext, Map<String, Object> env, String username, String password)
            throws NamingException {
        Map<String, ?> ldapConfig = setupDirContextEnvironment(queryContext, env, username, password);
        return new InitialDirContext(new Hashtable<>(ldapConfig));
    }

    /**
     * Called in order to set up the environment configuration passed to the
     * {@link InitialDirContext#InitialDirContext(Hashtable)} constructor
     *
     * @param  queryContext    The caller-specific query context
     * @param  env             The current environment setup
     * @param  username        The username - may be {@code null}/empty
     * @param  password        The password - may be {@code null}/empty
     * @return                 An updated environment configuration - can be a <U>new</U> instance or just the original
     *                         one with some changes in it
     * @throws NamingException If failed to set up the environment
     */
    protected Map<String, Object> setupDirContextEnvironment(
            C queryContext, Map<String, Object> env, String username, String password)
            throws NamingException {
        if (!env.containsKey(Context.PROVIDER_URL)) {
            int port = getPort();
            ValidateUtils.checkTrue(port > 0, "No port configured");
            String url = ValidateUtils.checkNotNullAndNotEmpty(getProtocol(), "No protocol")
                         + "://" + ValidateUtils.checkNotNullAndNotEmpty(getHost(), "No host")
                         + ":" + port;
            env.put(Context.PROVIDER_URL, url);
        }

        String mode = Objects.toString(env.get(Context.SECURITY_AUTHENTICATION), null);
        boolean anonymous = GenericUtils.isEmpty(mode) || PropertyResolverUtils.isNoneValue(mode);
        if (!anonymous) {
            Object[] bindParams = { username, password };
            if (!env.containsKey(Context.SECURITY_PRINCIPAL)) {
                String bindDN = Objects.requireNonNull(bindDNPattern, "No bind DN pattern").format(bindParams);
                env.put(Context.SECURITY_PRINCIPAL, ValidateUtils.checkNotNullAndNotEmpty(bindDN, "No bind DN"));
            }

            if (!env.containsKey(Context.SECURITY_CREDENTIALS)) {
                String bindPassword
                        = Objects.requireNonNull(bindPasswordPattern, "No bind password pattern").format(bindParams);
                env.put(Context.SECURITY_CREDENTIALS, ValidateUtils.checkNotNullAndNotEmpty(bindPassword, "No bind password"));
            }
        }

        return env;
    }

    protected String resolveBaseDN(C queryContext, Map<?, ?> ldapConfig, String username, String password)
            throws NamingException {
        Object[] bindParams = { username, password };
        return Objects.requireNonNull(baseDNPattern, "No base DN pattern").format(bindParams);
    }

    protected String resolveSearchFilter(C queryContext, Map<?, ?> ldapConfig, String username, String password)
            throws NamingException {
        Object[] bindParams = { username, password };
        return Objects.requireNonNull(searchFilterPattern, "No search filter pattern").format(bindParams);
    }

    protected void processSearchResult(
            C queryContext, Map<?, ?> ldapConfig, Map<String, Object> attrsMap,
            int resultIndex, SearchResult result)
            throws NamingException {
        String dn = result.getName();
        accumulateAttributeValue(queryContext, attrsMap, Context.AUTHORITATIVE, dn);

        Attributes attrs = result.getAttributes();
        NamingEnumeration<? extends Attribute> attrVals = attrs.getAll();
        try {
            while (attrVals.hasMore()) {
                processResultAttributeValue(queryContext, ldapConfig, dn, resultIndex, attrsMap, attrVals.next());
            }
        } finally {
            attrVals.close();
        }
    }

    // returns the most up-to-date value mapped for the attribute
    protected Object processResultAttributeValue(
            C queryContext, Map<?, ?> ldapConfig,
            String dn, int resultIndex, Map<String, Object> attrsMap, Attribute a)
            throws NamingException {
        String attrID = a.getID();
        int numValues = a.size();
        for (int index = 0; index < numValues; index++) {
            Object attrVal = a.get(index);

            if (attrVal != null) {
                Object prev = accumulateAttributeValue(queryContext, attrsMap, attrID, attrVal);
                if (log.isTraceEnabled()) {
                    if (prev != null) {
                        log.trace("processResultAttributeValue({})[{}] multiple values: {} / {}",
                                dn, attrID, toString(prev), toString(attrVal));
                    } else {
                        log.trace("processResultAttributeValue({}) {} = {}", dn, attrID, toString(attrVal));
                    }
                }
            } else {
                if (log.isTraceEnabled()) {
                    log.trace("processResultAttributeValue({}) skip null attribute: {}", dn, attrID);
                }
            }

            if ((numValues > 1) && (!isAccumulateMultiValues())) {
                if (log.isTraceEnabled()) {
                    log.trace("processResultAttributeValue({})[{}] skip remaining {} values",
                            dn, attrID, numValues - 1);
                }

                break;
            }
        }

        return attrsMap.get(attrID);
    }

    @SuppressWarnings("unchecked")
    protected Object accumulateAttributeValue(C queryContext, Map<String, Object> attrsMap, String attrID, Object attrVal) {
        Object prev = attrsMap.put(attrID, attrVal);
        if (prev == null) {
            return null; // debug breakpoint
        }

        List<Object> values = null;
        if (prev instanceof List<?>) {
            values = (List<Object>) prev;
        } else {
            values = new ArrayList<>();
            values.add(prev);
            attrsMap.put(attrID, values);
        }

        values.add(attrVal);
        return values.get(values.size() - 2);
    }

    public static String toString(Object attrVal) {
        if (attrVal == null) {
            return null;
        }

        Class<?> attrType = attrVal.getClass();
        if (attrType.isArray()) {
            return (attrVal instanceof byte[]) ? BufferUtils.toHex((byte[]) attrVal) : Arrays.toString((Object[]) attrVal);
        }

        return attrVal.toString();
    }
}
