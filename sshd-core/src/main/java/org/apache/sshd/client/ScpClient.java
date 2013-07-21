package org.apache.sshd.client;

import java.io.IOException;

/**
 */
public interface ScpClient {

    void download(String remote, String local) throws IOException;

    void download(String remote, String local, boolean recursive) throws IOException;

    void download(String[] remote, String local) throws Exception;

    void download(String[] remote, String local, boolean recursive) throws Exception;

    void upload(String remote, String local) throws IOException;

    void upload(String remote, String local, boolean recursive) throws IOException;

    void upload(String[] local, String remote, boolean recursive) throws IOException;

}
