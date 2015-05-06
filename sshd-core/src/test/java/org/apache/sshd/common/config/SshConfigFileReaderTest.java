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

package org.apache.sshd.common.config;

import java.io.IOException;
import java.net.URL;
import java.util.Collection;
import java.util.List;
import java.util.Properties;

import org.apache.sshd.SshBuilder;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.BaseTest;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshConfigFileReaderTest extends BaseTest {
    public SshConfigFileReaderTest() {
        super();
    }

    @Test
    public void testReadFromURL() throws IOException {
        URL url=getClass().getResource("sshd_config");
        Assert.assertNotNull("Cannot locate test file", url);
        
        Properties  props=SshConfigFileReader.readConfigFile(url);
        Assert.assertFalse("No properties read", props.isEmpty());
        Assert.assertTrue("Unexpected commented property data", GenericUtils.isEmpty(props.getProperty("ListenAddress")));
        Assert.assertTrue("Unexpected non-existing property data", GenericUtils.isEmpty(props.getProperty(getCurrentTestName())));

        String  keysList=props.getProperty("HostKey");
        Assert.assertFalse("No host keys", GenericUtils.isEmpty(keysList));

        String[]    keys=GenericUtils.split(keysList, ',');
        Assert.assertTrue("No multiple keys", GenericUtils.length((Object[]) keys) > 1);
    }

    @Test
    public void testParseCiphersList() {
        List<? extends NamedResource>   expected=SshBuilder.BaseBuilder.DEFAULT_CIPHERS_PREFERENCE;
        Properties                      props=initProperties(SshConfigFileReader.CIPHERS_CONFIG_PROP, expected);
        testParsedFactoriesList(expected, SshConfigFileReader.getCiphers(props));
    }

    @Test
    public void testParseMacsList() {
        List<? extends NamedResource>   expected=SshBuilder.BaseBuilder.DEFAULT_MAC_PREFERENCE;
        Properties                      props=initProperties(SshConfigFileReader.MACS_CONFIG_PROP, expected);
        testParsedFactoriesList(expected, SshConfigFileReader.getMacs(props));
    }

    @Test
    public void testParseSignaturesList() {
        List<? extends NamedResource>   expected=SshBuilder.BaseBuilder.DEFAULT_SIGNATURE_PREFERENCE;
        Properties                      props=initProperties(SshConfigFileReader.HOST_KEY_ALGORITHMS_CONFIG_PROP, expected);
        testParsedFactoriesList(expected, SshConfigFileReader.getSignatures(props));
    }

    @Test
    public void testParseKexFactoriesList() {
        List<? extends NamedResource>   expected=SshBuilder.BaseBuilder.DEFAULT_KEX_PREFERENCE;
        Properties                      props=initProperties(SshConfigFileReader.KEX_ALGORITHMS_CONFIG_PROP, expected);
        testParsedFactoriesList(expected, SshConfigFileReader.getKexFactories(props));
    }

    @Test
    public void testGetCompression() {
        Properties  props=new Properties();
        for (CompressionConfigValue expected : CompressionConfigValue.VALUES) {
            props.setProperty(SshConfigFileReader.COMPRESSION_PROP, expected.name().toLowerCase());
            
            NamedResource   actual=SshConfigFileReader.getCompression(props);
            Assert.assertNotNull("No match for " + expected.name(), actual);
            Assert.assertEquals(expected.name(), expected.getName(), actual.getName());
        }
    }

    private static <T extends NamedResource> List<T> testParsedFactoriesList(List<? extends NamedResource> expected, List<T> actual) {
        Assert.assertEquals("Mismatched list size", expected.size(), GenericUtils.size(actual));
        for (int index=0; index < expected.size(); index++) {
            NamedResource   e=expected.get(index), a=actual.get(index);
            String          n1=e.getName(), n2=a.getName();
            Assert.assertEquals("Mismatched name at index=" + index, n1, n2);
        }
        
        return actual;
    }
    
    private static Properties initProperties(String key, Collection<?> values) {
        return initProperties(key, GenericUtils.join(values, ','));
    }

    private static Properties initProperties(String key, String value) {
        Properties  props=new Properties();
        props.setProperty(key, value);
        return props;
    }
}
