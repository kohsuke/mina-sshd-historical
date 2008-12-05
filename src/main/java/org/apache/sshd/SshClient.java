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
package org.apache.sshd;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.sshd.client.kex.DHG1;
import org.apache.sshd.client.kex.DHG14;
import org.apache.sshd.ClientSession;
import org.apache.sshd.common.AbstractFactoryManager;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.AbstractSessionIoHandler;
import org.apache.sshd.common.Cipher;
import org.apache.sshd.common.Compression;
import org.apache.sshd.common.KeyExchange;
import org.apache.sshd.common.Mac;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Signature;
import org.apache.sshd.common.cipher.AES128CBC;
import org.apache.sshd.common.cipher.AES192CBC;
import org.apache.sshd.common.cipher.AES256CBC;
import org.apache.sshd.common.cipher.BlowfishCBC;
import org.apache.sshd.common.cipher.TripleDESCBC;
import org.apache.sshd.common.compression.CompressionNone;
import org.apache.sshd.common.mac.HMACMD5;
import org.apache.sshd.common.mac.HMACMD596;
import org.apache.sshd.common.mac.HMACSHA1;
import org.apache.sshd.common.mac.HMACSHA196;
import org.apache.sshd.common.random.BouncyCastleRandom;
import org.apache.sshd.common.random.JceRandom;
import org.apache.sshd.common.signature.SignatureDSA;
import org.apache.sshd.common.signature.SignatureRSA;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.NoCloseInputStream;
import org.apache.sshd.common.util.NoCloseOutputStream;
import org.apache.mina.common.ConnectFuture;
import org.apache.mina.common.IoConnector;
import org.apache.mina.common.IoSession;
import org.apache.mina.transport.socket.nio.SocketConnector;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public class SshClient extends AbstractFactoryManager {

    private IoConnector connector;
    private ExecutorService executor;

    public SshClient() {
    }

    public void start() {
        executor = Executors.newCachedThreadPool();
        connector = new SocketConnector(Runtime.getRuntime().availableProcessors(),
                                        executor);
        ((SocketConnector) connector).setWorkerTimeout(0);
    }

    public void stop() {
        Set<SocketAddress> addresses = connector.getManagedServiceAddresses();
        for (SocketAddress address : addresses) {
            Set<IoSession> sessions = connector.getManagedSessions(address);
            for (IoSession ioSession : sessions) {
                try {
                    AbstractSession.getSession(ioSession).close();
                } catch (Exception e) {
                    // Ignore
                }
            }
        }
        executor.shutdown();
        try {
            executor.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
        }
        executor = null;
        connector = null;
    }

    public ClientSession connect(String host, int port) throws Exception {
        // TODO: throw an exception is the client is stopped
        assert host != null;
        assert port >= 0;
        if (connector == null) {
            throw new IllegalStateException("SshClient not started. Please call start() method before connecting to a server");
        }
        SocketAddress address = new InetSocketAddress(host, port);
        return connect(address);
    }

    public ClientSession connect(SocketAddress address) throws Exception {
        assert address != null;
        if (connector == null) {
            throw new IllegalStateException("SshClient not started. Please call start() method before connecting to a server");
        }
        ConnectFuture future = connector.connect(address, new AbstractSessionIoHandler() {
            protected AbstractSession createSession(IoSession ioSession) throws Exception {
                return new ClientSessionImpl(SshClient.this, ioSession);
            }
        });
        future.join();
        IoSession ioSession = future.getSession();
        ClientSessionImpl session = (ClientSessionImpl) AbstractSession.getSession(ioSession);
        session.waitFor(ClientSession.CLOSED | ClientSession.WAIT_AUTH, 0);
        // TODO: check if session is closed and throw an exception
        return session;
    }

    /**
     * Setup a default client.  The client does not require any additional setup.
     *
     * @return a newly create SSH client
     */
    public static SshClient setUpDefaultClient() {
        SshClient client = new SshClient();
        // DHG14 uses 2048 bits key which are not supported by the default JCE provider
        if (SecurityUtils.isBouncyCastleRegistered()) {
            client.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>>asList(
                    new DHG14.Factory(),
                    new DHG1.Factory()));
            client.setRandomFactory(new BouncyCastleRandom.Factory());
        } else {
            client.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>>asList(
                    new DHG1.Factory()));
            client.setRandomFactory(new JceRandom.Factory());
        }
        client.setCipherFactories(Arrays.<NamedFactory<Cipher>>asList(
                new AES128CBC.Factory(),
                new TripleDESCBC.Factory(),
                new BlowfishCBC.Factory(),
                new AES192CBC.Factory(),
                new AES256CBC.Factory()));
        // Compression is not enabled by default
        // sshd.setCompressionFactories(Arrays.<NamedFactory<Compression>>asList(
        //         new CompressionNone.Factory(),
        //         new CompressionZlib.Factory(),
        //         new CompressionDelayedZlib.Factory()));
        client.setCompressionFactories(Arrays.<NamedFactory<Compression>>asList(
                new CompressionNone.Factory()));
        client.setMacFactories(Arrays.<NamedFactory<Mac>>asList(
                new HMACMD5.Factory(),
                new HMACSHA1.Factory(),
                new HMACMD596.Factory(),
                new HMACSHA196.Factory()));
        client.setSignatureFactories(Arrays.<NamedFactory<Signature>>asList(
                new SignatureDSA.Factory(),
                new SignatureRSA.Factory()));
        return client;
    }

    /*=================================
          Main class implementation
     *=================================*/

    public static void main(String[] args) throws Exception {
        int port = 22;
        String host = null;
        String login = System.getProperty("user.name");
        List<String> command = null;
        int logLevel = 0;
        boolean error = false;

        for (int i = 0; i < args.length; i++) {
            if ("-p".equals(args[i])) {
                if (i + 1 >= args.length) {
                    System.err.println("option requires an argument: " + args[i]);
                    error = true;
                    break;
                }
                port = Integer.parseInt(args[++i]);
            } else if ("-l".equals(args[i])) {
                if (i + 1 >= args.length) {
                    System.err.println("option requires an argument: " + args[i]);
                    error = true;
                    break;
                }
                login = args[++i];
            } else if ("-v".equals(args[i])) {
                logLevel = 1;
            } else if ("-vv".equals(args[i])) {
                logLevel = 2;
            } else if ("-vvv".equals(args[i])) {
                logLevel = 3;
            } else if (args[i].startsWith("-")) {
                System.err.println("illegal option: " + args[i]);
                error = true;
                break;
            } else {
                if (host == null) {
                    host = args[i];
                } else {
                    if (command == null) {
                        command = new ArrayList<String>();
                    }
                    command.add(args[i]);
                }
            }
        }
        if (host == null) {
            System.err.println("hostname required");
            error = true;
        }
        if (error) {
            System.err.println("usage: ssh [-v[v][v]] [-l login] [-p port] hostname [command]");
            System.exit(-1);
        }

        // TODO: handle log level

        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        try {
            ClientSession session = client.connect(host, port);

            int ret = ClientSession.WAIT_AUTH;
            while ((ret & ClientSession.WAIT_AUTH) != 0) {
                System.out.print("Password:");
                BufferedReader r = new BufferedReader(new InputStreamReader(System.in));
                String password = r.readLine();
                session.authPassword(login, password);
                ret = session.waitFor(ClientSession.WAIT_AUTH | ClientSession.CLOSED | ClientSession.AUTHED, 0);
            }
            if ((ret & ClientSession.CLOSED) != 0) {
                System.err.println("error");
                System.exit(-1);
            }
            ClientChannel channel = session.createChannel("shell");
            channel.setIn(new NoCloseInputStream(System.in));
            channel.setOut(new NoCloseOutputStream(System.out));
            channel.setErr(new NoCloseOutputStream(System.err));
            channel.open();
            channel.waitFor(ClientChannel.CLOSED, 0);
            session.close();
        } finally {
            client.stop();
        }
    }

}
