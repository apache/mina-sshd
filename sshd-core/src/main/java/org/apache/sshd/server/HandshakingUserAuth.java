package org.apache.sshd.server;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.session.ServerSession;

/**
 * Extension of UserAuth for use with methods which require handshakes, such as gssapi-with-mic.
 * 
 * @author Richard Evans
 */

public interface HandshakingUserAuth extends UserAuth {
  
  /**
   * Set the service name from the original request.  This may be required for MIC verification later.
   * 
   * @param service The service name
   */
  
  void setServiceName(String service);
  
  /**
   * Check whether a particular message is handled here.
   * 
   * @param msg The message
   * 
   * @return <code>true</code> if the message is handled
   */
  
  boolean handles(SshConstants.Message msg);
  
  /**
   * Handle another step in the authentication process. 
   *
   * @param session the current ssh session
   * @param msg The message type
   * @param buffer the request buffer containing parameters specific to this request
   * @return <code>true</code> if the authentication succeeded, <code>false</code> if the authentication
   *          is not finished yet
   * @throws Exception if the authentication fails
   */
  
  Boolean next(ServerSession session, SshConstants.Message msg, Buffer buffer) throws Exception;
  
  /**
   * Get a user name which has been derived from the handshaking process, or the intial name if
   * nothing has been found.
   * 
   * @return The user name
   * 
   * @throws Exception if the request fails
   */
  
  String getUserName() throws Exception;
  
  /**
   * Free any system resources used by the module.
   */
  
  void destroy();
}
