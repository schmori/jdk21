package sun.security.ssl;

import sun.security.ssl.SSLExtension.SSLExtensionSpec;
import sun.security.ssl.SSLHandshake.HandshakeMessage;
import sun.security.ssl.SSLExtension.ExtensionConsumer;

import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;

import java.io.IOException;
import java.nio.ByteBuffer;

import java.util.*;

import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.FIDOServer;
import javax.net.ssl.CTAP2;
import javax.net.ssl.GCM;

import static sun.security.ssl.SSLExtension.CH_FIDO;
import static sun.security.ssl.SSLExtension.SH_FIDO;
import static sun.security.ssl.SSLExtension.CERT_FIDO;

/**
 * Pack of the "fido" extensions [/].
 */
final class FIDOExtension {
    static final HandshakeProducer chNetworkProducer =
            new CHFidoProducer();
    static final ExtensionConsumer chNetworkConsumer =
            new CHFidoConsumer();
    static final SSLStringizer chStringizer =
            new CHFidoStringizer();

    static final HandshakeProducer shNetworkProducer =
            new SHFidoProducer();
    static final ExtensionConsumer shNetworkConsumer =
            new SHFidoConsumer();
    static final SSLStringizer shStringizer =
            new SHFidoStringizer();

    static final HandshakeProducer certNetworkProducer =
            new CERTFidoProducer();
    static final ExtensionConsumer certNetworkConsumer =
            new CERTFidoConsumer();
    static final SSLStringizer certStringizer =
            new CERTFidoStringizer();


    /**
     * The "fido" extension in the ClientHello hanshake message.
     *
     * See master thesis for the specification of the extension.
     */
    static final class CHFidoSpec implements SSLExtensionSpec {
        ArrayList<byte[]> params;
        String fido;
        byte[] ephemeralUserID;
        String messageType;

        private CHFidoSpec(String messageType, String fido) {
            this.messageType = messageType;
            this.fido = fido;
        }
        private CHFidoSpec(String messageType, String fido, byte[] ephemeralUserID) {
            this.messageType = messageType;
            this.fido = fido;
            this.ephemeralUserID = ephemeralUserID;
        }

        private CHFidoSpec(HandshakeContext hc, ByteBuffer buffer) throws IOException {
            if (buffer.remaining() < 2) {
                throw hc.conContext.fatal(Alert.DECODE_ERROR,
                        new SSLProtocolException(
                                "Invalid fido extension: insufficient data"));
            }

            int dataLen = Record.getInt16(buffer);
            if ((dataLen == 0) || dataLen != buffer.remaining()) {
                throw hc.conContext.fatal(Alert.DECODE_ERROR,
                        new SSLProtocolException(
                                "Invalid fido extension: incomplete data. \n" +
                                "Data length: " + dataLen + "\n" +
                                "Buffer remaining: " + buffer.remaining()));
            }

            this.params = new ArrayList<byte[]>();
            while (buffer.hasRemaining()) {
                this.params.add(Record.getBytes16(buffer));
            }
        }

        @Override
        public String toString() {
            return String.format("CHFidoSpec");
        }
    }

    private static final
    class CHFidoStringizer implements SSLStringizer {
        @Override
        public String toString(HandshakeContext hc, ByteBuffer buffer) {
            return "";
        }
    }


    /**
     * Network data producer of a "fido" extension in the
     * ClientHello handshake message.
     */
    private static final
            class CHFidoProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private CHFidoProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                              HandshakeMessage message) throws IOException {
            // The producing happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext) context;

            // Is it a supported and enabled extension?
            if (!chc.sslConfig.isAvailable(CH_FIDO)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning(
                            "Ignore unavailable fido extension");
                }
                return null;
            }

            if (chc.sslConfig.fido == null) {
                SSLLogger.warning(
                        "fido not activated by client");
                return null;
            }

            // Produce the extension
            byte[] extData = new byte[0];

            if (chc.isResumption && (chc.resumingSession != null)) {
                // session resumption is suppressed.
            } else {
                CTAP2 ctap2 = new CTAP2();

                try {
                    ctap2.receiveEphemeralUserIDAndGcmKey();
                } catch (IOException | InterruptedException e) {
                    throw new RuntimeException(e);
                }

                byte[] ephemeralUserID = ctap2.getEphemeralUserID();
                byte[] gcmKey = ctap2.getGcmMasterKey();

                if (ephemeralUserID == null || ephemeralUserID.length == 0 || gcmKey == null || gcmKey.length == 0) {
                    throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "ephemeralID or gcm key is empty.");
                }

                if (Arrays.equals(ephemeralUserID, new byte[1])) { // pre registration & authentication
                    chc.fido = chc.sslConfig.fido;
                    String messageType = "0";

                    // pre registration & authentication
                    int fidoLen = messageType.getBytes().length + 2 + chc.fido.getBytes().length + 2;
                    extData = new byte[fidoLen + 2];
                    ByteBuffer m = ByteBuffer.wrap(extData);
                    Record.putInt16(m, fidoLen);
                    Record.putBytes16(m, messageType.getBytes());
                    Record.putBytes16(m, chc.fido.getBytes());

                    System.out.printf("TLS Client: Pre %s Indication\n", (chc.fido.equals("0")?"Registration":"Authentication"));

                    // Update the context.
                    chc.handshakeExtensions.put(CH_FIDO,
                            new CHFidoSpec(messageType, chc.fido));
                } else { // registration & authentication
                    chc.fido = chc.sslConfig.fido;
                    chc.gcmKey = gcmKey;

                    byte[] encoded_fido = chc.fido.getBytes();
                    String messageType = "3";

                    int dataLen = messageType.getBytes().length + 2 + encoded_fido.length + 2 + ephemeralUserID.length + 2;
                    extData = new byte[dataLen + 2];
                    ByteBuffer m = ByteBuffer.wrap(extData);
                    Record.putInt16(m, dataLen);
                    Record.putBytes16(m, messageType.getBytes());
                    Record.putBytes16(m, encoded_fido);
                    Record.putBytes16(m, ephemeralUserID);

                    System.out.printf("TLS Client: %s Indication\n", (chc.fido.equals("0")?"Registration":"Authentication"));

                    // Update the context.
                    chc.handshakeExtensions.put(CH_FIDO,
                            new CHFidoSpec(messageType, chc.fido, ephemeralUserID));
                }
            }

            return extData;
        }
    }

    /**
     * Network data consumer of a "fido" extension in the
     * ClientHello handshake message.
     */
    private static final
            class CHFidoConsumer implements ExtensionConsumer {
        // Prevent instantiation of this class.
        private CHFidoConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                            HandshakeMessage message, ByteBuffer buffer) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            // Is it a supported and enabled extension?
            if (!shc.sslConfig.isAvailable(CH_FIDO)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Ignore unavailable extension: " + CH_FIDO.name);
                }
                return;     // ignore the extension
            }

            // Parse the extension.
            CHFidoSpec spec = new CHFidoSpec(shc, buffer);

            if (spec.params == null) return;

            String messageType = new String(spec.params.get(0));
            shc.fido = new String(spec.params.get(1));

            if (shc.isResumption && (shc.resumingSession != null)) {
                // session resumption is suppressed.
            } else {
                if (messageType.equals("0")) { // pre registration & authentication
                    if (spec.params.size() != 2) throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "wrong messages. should be fido mode and message type.");
                    System.out.printf("TLS Server: Received Pre %s Indication\n", (shc.fido.equals("0")?"Registration":"Authentication"));
                } else if (messageType.equals("3")) { // registration & authentication
                    if (spec.params.size() != 3) throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "wrong messages. should be fido mode, message type and ephemeral id.");
                    FIDOServer fidoServer = new FIDOServer();

                    try {
                        fidoServer.receiveEphemeralUserIDAndGcmKey();
                    } catch (IOException | InterruptedException e) {
                        throw new RuntimeException(e);
                    }

                    shc.gcmKey = fidoServer.getGcmKey();

                    if (!Arrays.equals(spec.params.get(2), fidoServer.getEphemeralUserID())) {
                        throw new IOException("TLS Server: ephemeralUserIDs do not match.");
                    } else {
                        System.out.println("TLS Server: ephemeralUserIDs do match.");
                    }
                    System.out.printf("TLS Server: Received %s Indication\n", (shc.fido.equals("0")?"Registration":"Authentication"));
                } else {
                    throw new IOException("TLS Server: messageType is invalid.");
                }
            }

            // Update extension
            shc.handshakeExtensions.put(CH_FIDO, spec);
        }
    }

    /**
     * The "fido" extension in the ServerHello hanshake message.
     *
     * See master thesis for the specification of the extension.
     */
    static final class SHFidoSpec implements SSLExtensionSpec {
        ArrayList<byte[]> params;
        String messageType;
        byte[] options;

        byte[] ephemeralUserID;
        byte[] key;

        String rpID;
        String username;
        String rk;

        private SHFidoSpec(String messageType, byte[] ephemeralUserID, byte[] key) {
            this.messageType = messageType;
            this.ephemeralUserID = ephemeralUserID;
            this.key = key;
        }

        private SHFidoSpec(String messageType, byte[] options) {
            this.messageType = messageType;
            this.options = options;
        }

        private SHFidoSpec(HandshakeContext hc, ByteBuffer buffer) throws IOException {
            if (buffer.remaining() < 2) {
                throw hc.conContext.fatal(Alert.DECODE_ERROR,
                        new SSLProtocolException(
                                "Invalid fido extension: " +
                                        "insufficient data (length=" + buffer.remaining() + ")"));
            }

            int dataLen = Record.getInt16(buffer);
            if ((dataLen == 0) || dataLen != buffer.remaining()) {
                throw hc.conContext.fatal(Alert.DECODE_ERROR,
                        new SSLProtocolException(
                                "Invalid fido extension: incomplete data. \n" +
                                        "Data length: " + dataLen + "\n" +
                                        "Buffer remaining: " + buffer.remaining()));
            }


            this.params = new ArrayList<byte[]>();
            while (buffer.hasRemaining()) {
                this.params.add(Record.getBytes16(buffer));
            }
        }

        @Override
        public String toString() {
            return String.format("SHFidoSpec");
        }
    }

    private static final
    class SHFidoStringizer implements SSLStringizer {
        @Override
        public String toString(HandshakeContext hc, ByteBuffer buffer) {
            return "";
        }
    }

    /**
     * Network data producer of a "fido" extension in the
     * ServerHello handshake message.
     */
    private static final
            class SHFidoProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private SHFidoProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                              HandshakeMessage message) throws IOException {
            // The producing happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            // Is it a supported and enabled extension?
            if (!shc.sslConfig.isAvailable(SH_FIDO)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Ignore unavailable extension: " + SH_FIDO.name);
                }
                return null;     // ignore the extension
            }

            // In response to "fido" extension request from client only
            CHFidoSpec spec = (CHFidoSpec)
                    shc.handshakeExtensions.get(CH_FIDO);
            if (spec == null || spec.params == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest(
                            "Ignore unavailable extension: " + SH_FIDO.name);
                }
                return null;        // ignore the extension
            }

            // Produce the extension
            byte[] extData = new byte[0];
            String messageType = new String(spec.params.get(0));

            if (shc.isResumption && (shc.resumingSession != null)) {
                // session resumption is suppressed.
            } else {
                if (messageType.equals("0")) { // pre registration and authentication
                    System.out.println("TLS Server: send ephemeralUserID and gcm key to TLS Client");

                    byte[] ephemeralUserID = new byte[32]; // up to 32 byte
                    byte[] gcmKey = new byte[32]; // 32 byte

                    try {
                        SecureRandom.getInstanceStrong().nextBytes(ephemeralUserID);
                        SecureRandom.getInstanceStrong().nextBytes(gcmKey);
                    } catch (NoSuchAlgorithmException e) {
                        throw new RuntimeException(e);
                    }

                    FIDOServer fidoServer = new FIDOServer(ephemeralUserID, gcmKey);

                    try {
                        fidoServer.sendEphemeralUserIDAndGcmKey();
                    } catch (IOException | InterruptedException e) {
                        throw new RuntimeException(e);
                    }

                    messageType = "1";
                    int userLen = gcmKey.length + 2 + messageType.getBytes().length + 2 + ephemeralUserID.length + 2; // +2 parameter length

                    extData = new byte[userLen + 2];
                    ByteBuffer m = ByteBuffer.wrap(extData);
                    Record.putInt16(m, userLen);
                    Record.putBytes16(m, messageType.getBytes());
                    Record.putBytes16(m, ephemeralUserID);
                    Record.putBytes16(m, gcmKey);

                    // Update the context.
                    shc.ephemeralUserID = ephemeralUserID;

                    shc.handshakeExtensions.put(SH_FIDO,
                            new SHFidoSpec(messageType, ephemeralUserID, gcmKey));
                } else if (messageType.equals("3")) {
                    FIDOServer fidoServer = new FIDOServer();

                    try {
                        if (shc.fido.equals("0")) {
                            fidoServer.receiveCredOptions();
                            System.out.println("Received PublicKeyCredentialCreationOptions from FIDO Server.");
                        }
                        if (shc.fido.equals("1")) {
                            fidoServer.receiveReqOptions();
                            System.out.println("Received PublicKeyCredentialRequestOptions from FIDO Server.");
                        }
                    } catch (IOException | InterruptedException | ClassNotFoundException e) {
                        System.out.println("TLS Server: Problems while connecting to FIDO client.");
                        throw new RuntimeException(e);
                    }

                    byte[] options = fidoServer.getOptions();

                    messageType = "4";

                    String key_base64 = Base64.getUrlEncoder().encodeToString(shc.gcmKey);
                    byte[] encrypted_options = new byte[0];

                    try {
                        encrypted_options = GCM.encrypt(key_base64, options);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }

                    int len = messageType.getBytes().length + 2 + encrypted_options.length + 2;

                    extData = new byte[len + 2];
                    ByteBuffer m = ByteBuffer.wrap(extData);
                    Record.putInt16(m, len);
                    Record.putBytes16(m, messageType.getBytes());
                    Record.putBytes16(m, encrypted_options);

                    // Update the context.
                    shc.handshakeExtensions.put(SH_FIDO,
                            new SHFidoSpec(messageType, encrypted_options));
                } else {
                    throw new IOException("TLS Server: messageType is invalid.");
                }
            }

            return extData;
        }
    }

    /**
     * Network data consumer of a "fido" extension in the
     * ServerHello handshake message.
     */
    private static final
            class SHFidoConsumer implements ExtensionConsumer {
        // Prevent instantiation of this class.
        private SHFidoConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                            HandshakeMessage message, ByteBuffer buffer) throws IOException {
            // The consuming happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            // Is it a supported and enabled extension?
            if (!chc.sslConfig.isAvailable(SH_FIDO)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Ignore unavailable extension: " + SH_FIDO.name);
                }
                return;     // ignore the extension
            }

            SHFidoSpec spec = new SHFidoSpec(chc, buffer);

            if (spec == null || spec.params == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest(
                            "Ignore unavailable extension: " + SH_FIDO.name);
                }
                return;        // ignore the extension
            }

            String messageType = new String(spec.params.get(0));

            // Parse the extension.
            if (chc.isResumption && (chc.resumingSession != null)) {
                // session resumption is suppressed.
            } else {
                if (messageType.equals("1")) { // pre registration & authentication
                    if (!messageType.equals("1")) throw new IOException("TLS Client: wrong messageType when receiving ephemeralUserID");
                    ArrayList<byte[]> params = spec.params;
                    if (params.size() != 3) throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Missing gmc key or ephemeral id.");
                    byte[] ephemeralUserID = params.get(1);
                    byte[] key = params.get(2);

                    CTAP2 ctap2 = new CTAP2();
                    ctap2.setEphemeralUserID(ephemeralUserID);
                    ctap2.setGcmMasterKey(key);

                    try {
                        ctap2.sendEphemeralUserIDAndGcmKey();
                    } catch (IOException | InterruptedException e) {
                        throw new RuntimeException(e);
                    }

                    System.out.println("TLS Client: received ephemeralUserID by TLS Server");

                    chc.handshakeExtensions.put(SH_FIDO,
                            spec);
                } else if (messageType.equals("4")) {
                    if (spec.params.size() != 2) throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Missing options.");
                    byte[] encrypted_options = spec.params.get(1);

                    String key_base64 = Base64.getUrlEncoder().encodeToString(chc.gcmKey);
                    byte[] options = new byte[0];

                    try {
                        options = GCM.decrypt(encrypted_options, key_base64);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }

                    CTAP2 ctap2 = new CTAP2(options);

                    try {
                        if (chc.fido.equals("0")) {
                            ctap2.getClientRegResponse();
                        }
                        if (chc.fido.equals("1")) {
                            ctap2.getClientAuthResponse();
                        }
                    } catch (IOException | InterruptedException e) {
                        System.out.println("Registration: Problems while connecting to CTAP2 server.");
                        throw new RuntimeException(e);
                    }

                    byte[] response = ctap2.getResponse();

                    System.out.println("TLS Client: Response by CTAP2 server: " + new String(response));

                    // Update the context.
                    chc.response = response;

                    chc.handshakeExtensions.put(SH_FIDO,
                            spec);
                } else {
                    throw new IOException("TLS Client: messageType is invalid.");
                }
            }
        }
    }

    /**
     * The "fido" extension in the Finished handshake message.
     *
     * See master thesis for the specification of the extension.
     */
    static final class CERTFidoSpec implements SSLExtensionSpec {
        ArrayList<byte[]> params;
        String messageType;

        byte[] ticket;
        String username;

        byte[] response;

        private CERTFidoSpec(String messageType, byte[] data) { // data = username or response
            this.messageType = messageType;
            params = new ArrayList<byte[]>();
            params.add(data);
        }

        private CERTFidoSpec(String messageType, byte[] ticket, String username) {
            this.messageType = messageType;
            this.ticket = ticket;
            this.username = username;
        }

        private CERTFidoSpec(HandshakeContext hc, ByteBuffer buffer) throws IOException {
            if (buffer.remaining() < 2) {
                throw hc.conContext.fatal(Alert.DECODE_ERROR,
                        new SSLProtocolException(
                                "Invalid fido extension: insufficient data"));
            }

            int dataLen = Record.getInt16(buffer);
            if ((dataLen == 0) || dataLen != buffer.remaining()) {
                throw hc.conContext.fatal(Alert.DECODE_ERROR,
                        new SSLProtocolException(
                                "Invalid fido extension: incomplete data. \n" +
                                        "Data length: " + dataLen + "\n" +
                                        "Buffer remaining: " + buffer.remaining()));
            }

            this.params = new ArrayList<byte[]>();
            while (buffer.hasRemaining()) {
                this.params.add(Record.getBytes16(buffer));
            }
        }

        @Override
        public String toString() {
            return String.format("CERTFidoSpec");
        }
    }

    private static final
    class CERTFidoStringizer implements SSLStringizer {
        @Override
        public String toString(HandshakeContext hc, ByteBuffer buffer) {
            return "";
        }
    }

    /**
     * Network data producer of a "fido" extension in the
     * CERTIFICATE handshake message.
     */
    private static final
    class CERTFidoProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private CERTFidoProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                              HandshakeMessage message) throws IOException {
            byte[] extData = new byte[0];
            HandshakeContext hc = (HandshakeContext)context;

            if (hc.sslConfig.isClientMode) {
                // The producing happens in client side only.
                ClientHandshakeContext chc = (ClientHandshakeContext) context;

                // Is it a supported and enabled extension?
                if (!chc.sslConfig.isAvailable(CERT_FIDO)) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine(
                                "Ignore unavailable extension: " + CERT_FIDO.name);
                    }
                    return null;     // ignore the extension
                }

                // In response to "fido" extension message from client
                SHFidoSpec spec = (SHFidoSpec)
                        chc.handshakeExtensions.get(SH_FIDO);
                if (spec == null) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.finest(
                                "Ignore unavailable extension: " + CERT_FIDO.name);
                    }
                    return null;        // ignore the extension
                }

                String messageType = new String(spec.params.get(0));

                // Produce the extension.
                if (chc.isResumption && (chc.resumingSession != null)) {
                    // session resumption is suppressed.
                } else {
                    if (messageType.equals("1")) {
                        if (chc.fido.equals("0")) { // pre registration
                            System.out.println("TLS Client: send ticket and username to TLS Server.");

                            byte[] ticket = chc.sslConfig.ticket;
                            byte[] encoded_username = chc.sslConfig.username.getBytes();
                            messageType = "2";

                            int dataLen = messageType.getBytes().length + 2 + ticket.length + 2 + encoded_username.length + 2;
                            extData = new byte[dataLen + 2];
                            ByteBuffer m = ByteBuffer.wrap(extData);
                            Record.putInt16(m, dataLen);
                            Record.putBytes16(m, messageType.getBytes());
                            Record.putBytes16(m, ticket);
                            Record.putBytes16(m, encoded_username);

                            // Update the context.
                            chc.handshakeExtensions.put(CERT_FIDO,
                                    new CERTFidoSpec(messageType, ticket, chc.sslConfig.username));
                        } else if (chc.fido.equals("1")) { // pre authentication
                            System.out.println("TLS Client: send username to TLS Server.");

                            byte[] encoded_username = chc.sslConfig.username.getBytes();
                            messageType = "2";

                            int dataLen = messageType.getBytes().length + 2 + encoded_username.length + 2;
                            extData = new byte[dataLen + 2];
                            ByteBuffer m = ByteBuffer.wrap(extData);
                            Record.putInt16(m, dataLen);
                            Record.putBytes16(m, messageType.getBytes());
                            Record.putBytes16(m, encoded_username);

                            // Update the context.
                            chc.handshakeExtensions.put(CERT_FIDO,
                                    new CERTFidoSpec(messageType, encoded_username));
                        }
                    } else if (messageType.equals("4")) {
                        byte[] response = chc.response;
                        messageType = "5";

                        System.out.println("TLS Client: send response data to TLS Server");

                        int responseLen = messageType.getBytes().length + 2 + response.length + 2;
                        extData = new byte[responseLen + 2];
                        ByteBuffer m = ByteBuffer.wrap(extData);
                        Record.putInt16(m, responseLen);
                        Record.putBytes16(m, messageType.getBytes());
                        Record.putBytes16(m, response);

                        // Update the context.
                        chc.handshakeExtensions.put(CERT_FIDO,
                                new CERTFidoSpec(messageType, response));
                    } else {
                        throw new IOException("TLS Client: messageType is invalid.");
                    }
                }
            }

            return extData;
        }
    }

    /**
     * Network data consumer of a "fido" extension in the
     * CERTIFICATE handshake message.
     */
    private static final
    class CERTFidoConsumer implements ExtensionConsumer {
        // Prevent instantiation of this class.
        private CERTFidoConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                            HandshakeMessage message, ByteBuffer buffer) throws IOException {
            HandshakeContext hc = (HandshakeContext)context;
            if (!hc.sslConfig.isClientMode) {
                // The consuming happens in server side only.
                ServerHandshakeContext shc = (ServerHandshakeContext) context;

                CERTFidoSpec spec = new CERTFidoSpec(shc, buffer);
                if (spec.params == null) return;
                String messageType = new String(spec.params.get(0));

                if (shc.isResumption && (shc.resumingSession != null)) {
                    // session resumption is suppressed.
                } else {
                    if (messageType.equals("2")) {
                        if (shc.fido.equals("0")) { // pre registration
                            if (spec.params.size() != 3) throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Missing ticket or username.");
                            byte[] ticket = spec.params.get(1);
                            byte[] username = spec.params.get(2);
                            System.out.println("TLS Server: received ticket and username by TLS Client.");
                            System.out.println("User with name " + new String(username) + " wants to register yubico token.");

                            if (Arrays.equals(shc.sslConfig.ticket, ticket)) {
                                FIDOServer fidoServer = new FIDOServer(new String(username), "0");

                                try {
                                    fidoServer.sendUsername();
                                } catch (IOException | InterruptedException e) {
                                    System.out.println("Registration: Problems while connecting to FIDO client.");
                                    throw new RuntimeException(e);
                                }

                                System.out.println("Pre Registration was successful.");
                            } else {
                                throw new IOException("Pre Registration failed. Wrong ticket");
                            }
                        } else if (shc.fido.equals("1")) { // pre authentication
                            if (spec.params.size() != 2) throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Missing username.");
                            byte[] username = spec.params.get(1);
                            System.out.println("Pre Authentication was successful.");
                            System.out.println("User with name " + new String(username) + " wants to authenticate yubico token.");

                            FIDOServer fidoServer = new FIDOServer(new String(username), "1");

                            try {
                                fidoServer.sendUsername();
                            } catch (IOException | InterruptedException e) {
                                System.out.println("Registration: Problems while connecting to FIDO client.");
                                throw new RuntimeException(e);
                            }
                        }
                    } else if (messageType.equals("5")) {
                        if (spec.params.size() != 2) throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Missing response.");
                        byte[] response = spec.params.get(1);
                        FIDOServer fidoServer = null;
                        if (shc.fido.equals("0")) {
                            fidoServer = new FIDOServer(response, "3"); // registration
                        }

                        if (shc.fido.equals("1")) {
                            fidoServer = new FIDOServer(response, "6"); // authentication
                        }

                        try {
                            fidoServer.sendResponseToClient();
                        } catch (IOException | InterruptedException e) {
                            System.out.println("TLS Server: Problems while connecting to FIDO server.");
                            throw new RuntimeException(e);
                        }

                        if (shc.fido.equals("0")) System.out.println("TLS Server: Registration was successful.");
                        if (shc.fido.equals("1")) System.out.println("TLS Server: Authentication was successful.");
                    } else {
                        throw new IOException("TLS Server: messageType is invalid.");
                    }
                }
            }
        }
    }
}