package org.apache.sshd.client.config.hosts;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class KnownHostEntryTest {
    @Test
    public void testIsHostMatch_hashWithPort() {
        // line generated `ssh xenon@localhost -p 10022 hostname` (SSH-2.0-OpenSSH_7.5)
        String line = "|1|qhjoqX12EcnwZO3KNbpoFbxrdYE=|J+voEFzRbRL49TiHV+jbUfaS+kg= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJTsDTYFSYyRMlOec6JBfC8dEFqHNNWu7n8N0niS1zmHpggX+L4cndxhJPE0ILi9otHO7h0mp0cmqqho2tsX8lc=";
        KnownHostEntry known = KnownHostEntry.parseKnownHostEntry(line);

        assertTrue(known.isHostMatch("localhost", 10022));
        // other ports should not match
        assertFalse(known.isHostMatch("localhost", 0));
        assertFalse(known.isHostMatch("localhost", 2222));
        assertFalse(known.isHostMatch("localhost", 22));
    }

    @Test
    public void testIsHostMatch_hashWithoutPort() {
        // line generated `ssh xenon@localhost hostname` (SSH-2.0-OpenSSH_7.5)
        String line = "|1|vLQs+atPgodQmPes21ZaMSgLD0s=|A2K2Ym0ZPtQmD8kB3FVViQvQ7qQ= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJTsDTYFSYyRMlOec6JBfC8dEFqHNNWu7n8N0niS1zmHpggX+L4cndxhJPE0ILi9otHO7h0mp0cmqqho2tsX8lc=";
        KnownHostEntry known = KnownHostEntry.parseKnownHostEntry(line);

        assertTrue(known.isHostMatch("localhost", 0));
        assertTrue(known.isHostMatch("localhost", 22));
        // other ports should not match
        assertFalse(known.isHostMatch("localhost", 2222));
    }
}
