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

package org.apache.sshd.common;

import java.util.Map;
import java.util.TreeMap;

import org.apache.sshd.util.BaseTestSupport;
import org.junit.Test;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class FactoryManagerUtilsTest extends BaseTestSupport {
    public FactoryManagerUtilsTest() {
        super();
    }

    @Test
    public void testLongProperty() {
        final long      expected=System.currentTimeMillis();
        final String    name=getCurrentTestName();
        
        Session session = createMockSession();
        assertEquals("Mismatched empty props value", expected, FactoryManagerUtils.getLongProperty(session, name, expected));

        FactoryManagerUtils.updateProperty(session, name, expected);
        testLongProperty(session, name, expected);
        
        FactoryManagerUtils.updateProperty(session, name, Long.toString(expected));
        testLongProperty(session, name, expected);
    }
    
    private void testLongProperty(Session session, String name, long expected) {
        FactoryManager  manager = session.getFactoryManager();
        Map<String,?>   props = manager.getProperties();
        Object          value = props.get(name);
        Class<?>        type = value.getClass();
        String          storage = type.getSimpleName();

        {
            Long actual = FactoryManagerUtils.getLong(session, name);
            assertNotNull("No actual Long value found for storage as " + storage, actual);
            assertEquals("Mismatched values on Long retrieval for storage as " + storage, expected, actual.longValue());
        }

        {
            String actual = FactoryManagerUtils.getString(session, name);
            assertNotNull("No actual String value found for storage as " + storage, actual);
            assertEquals("Mismatched values on String retrieval for storage as " + storage, Long.toString(expected), actual.toString());
        }
    }

    @Test
    public void testIntegerProperty() {
        final int      expected=3777347;
        final String   name=getCurrentTestName();
        
        Session session = createMockSession();
        assertEquals("Mismatched empty props value", expected, FactoryManagerUtils.getIntProperty(session, name, expected));

        FactoryManagerUtils.updateProperty(session, name, expected);
        testIntegerProperty(session, name, expected);
        
        FactoryManagerUtils.updateProperty(session, name, Integer.toString(expected));
        testIntegerProperty(session, name, expected);

        // store as Long but retrieve as Integer
        FactoryManagerUtils.updateProperty(session, name, Long.valueOf(expected));
        testIntegerProperty(session, name, expected);
    }
    
    private void testIntegerProperty(Session session, String name, int expected) {
        FactoryManager  manager = session.getFactoryManager();
        Map<String,?>   props = manager.getProperties();
        Object          value = props.get(name);
        Class<?>        type = value.getClass();
        String          storage = type.getSimpleName();

        {
            Integer actual = FactoryManagerUtils.getInteger(session, name);
            assertNotNull("No actual Long value found for storage as " + storage, actual);
            assertEquals("Mismatched values on Long retrieval for storage as " + storage, expected, actual.intValue());
        }

        {
            String actual = FactoryManagerUtils.getString(session, name);
            assertNotNull("No actual String value found for storage as " + storage, actual);
            assertEquals("Mismatched values on String retrieval for storage as " + storage, Long.toString(expected), actual.toString());
        }
    }

    @Test
    public void testBooleanProperty() {
        for (final boolean expected : new boolean[] { false, true }) {
            final String   name=getCurrentTestName();
            
            Session session = createMockSession();
            assertEquals("Mismatched empty props value", expected, FactoryManagerUtils.getBooleanProperty(session, name, expected));
    
            FactoryManagerUtils.updateProperty(session, name, expected);
            testBooleanProperty(session, name, expected);
            
            FactoryManagerUtils.updateProperty(session, name, Boolean.toString(expected));
            testBooleanProperty(session, name, expected);
        }
    }
    
    private void testBooleanProperty(Session session, String name, boolean expected) {
        FactoryManager  manager = session.getFactoryManager();
        Map<String,?>   props = manager.getProperties();
        Object          value = props.get(name);
        Class<?>        type = value.getClass();
        String          storage = type.getSimpleName();

        {
            Boolean actual = FactoryManagerUtils.getBoolean(session, name);
            assertNotNull("No actual Long value found for storage as " + storage, actual);
            assertEquals("Mismatched values on Long retrieval for storage as " + storage, expected, actual.booleanValue());
        }

        {
            String actual = FactoryManagerUtils.getString(session, name);
            assertNotNull("No actual String value found for storage as " + storage, actual);
            assertEquals("Mismatched values on String retrieval for storage as " + storage, Boolean.toString(expected), actual.toString());
        }
    }

    private Session createMockSession() {
        Map<String,Object>  props = new TreeMap<String,Object>(String.CASE_INSENSITIVE_ORDER);
        FactoryManager      manager = Mockito.mock(FactoryManager.class);
        Mockito.when(manager.getProperties()).thenReturn(props);
        
        Session session = Mockito.mock(Session.class);
        Mockito.when(session.getUsername()).thenReturn(getCurrentTestName());
        Mockito.when(session.getFactoryManager()).thenReturn(manager);
        return session;
    }
}
