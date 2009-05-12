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
package org.apache.sshd.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

/**
 * This factory is used by SSH server when the client connected requests the creation
 * of a shell.
 *
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ShellFactory {

    /**
     * Create a shell.
     * This method is not supposed to throw any exception.
     * Exceptions should be thrown when calling {@link Shell#start(java.util.Map)}
     * method on the shell to start it.
     *
     * @return the newly create shell
     */
    Shell createShell();

    /**
     * Represents a shell that can be used in an interactive mode to send command.
     * This shell have direct streams, meaning those streams will be provided by the ssh server
     * for the shell to use directy. This interface is suitable for implementing shells in java,
     * rather than using an external process.  For wrapping such processes or using inverted streams,
     * see {@link org.apache.sshd.server.shell.InvertedShellWrapper}.
     */
    public interface Shell {

        /**
         * Set the input stream that can be used by the shell to read input.
         * @param in
         */
        void setInputStream(InputStream in);

        /**
         * Set the output stream that can be used by the shell to write its output.
         * @param out
         */
        void setOutputStream(OutputStream out);

        /**
         * Set the error stream that can be used by the shell to write its errors.
         * @param err
         */
        void setErrorStream(OutputStream err);

        /**
         * Set the callback that the shell has to call when it is closed.
         */
        void setExitCallback(ExitCallback callback);

        /**
         * Starts the shell.
         * All streams must have been set before calling this method.
         *
         * @param env
         * @throws Exception
         */
        void start(Map<String,String> env) throws IOException;

        /**
         * Destroy the shell.
         * This method can be called by the SSH server to destroy the shell because
         * the client has disconnected somehow.
         */
        void destroy();

    }

    /**
     * Callback used by the shell to notify the SSH server is has exited
     */
    public interface ExitCallback {

        /**
         * Informs the SSH server that the shell has exited
         *
         * @param exitValue the exit value
         */
        void onExit(int exitValue);

    }

}
