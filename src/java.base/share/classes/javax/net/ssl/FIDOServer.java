package javax.net.ssl;

import javax.net.SocketFactory;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.nio.charset.StandardCharsets;

/**
 * This class acts as fido socket.
 */
public final class FIDOServer {

    private int fidoPort = 6666;
    private String hostname = "localhost";
    private byte[] response;
    private String username;
    private byte[] ephemeralUserID;
    private byte[] options;
    private String indication;
    private byte[] gcmKey;


    /**
     * Empty Constructor
     *
     * */
    public FIDOServer() {
    }

    /**
     * Constructor
     *
     * @param response given by CTAP2 server
     * @param indication given by CTAP2 server
     * */
    public FIDOServer(byte[] response, String indication) {
        this.response = response;
        this.indication = indication;
    }

    /**
     * Constructor
     *
     * @param ephemeralUserID given by TLS server
     * @param gcmKey given by TLS server
     * */
    public FIDOServer(byte[] ephemeralUserID, byte[] gcmKey) {
        this.ephemeralUserID = ephemeralUserID;
        this.gcmKey = gcmKey;
    }

    /**
     * Constructor
     *
     * @param username given by TLS client
     * @param indication given by CTAP2 server
     * */
    public FIDOServer(String username, String indication) {
        this.username = username;
        this.indication = indication;
    }

    /**
     * send ephemeralUserID and gcmkey to outer FIDO server.
     * Connect to FIDO server which is intialized outside of the sdk library.
     * Not best practice, but enough for PoC implementation.
     *
     * @throws IOException incase something happens
     * @throws InterruptedException incase something happens
     * */
    public void sendEphemeralUserIDAndGcmKey() throws IOException, InterruptedException {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(new String[] {"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"});
        SocketFactory factory = SSLSocketFactory.getDefault();

        try (SSLSocket socket = (SSLSocket) factory.createSocket(hostname, fidoPort)) {
            System.out.println("TLS Server: Send ephemeralUserID and gcm key to FIDO Server");
            socket.setSSLParameters(params);

            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));

            byte[] indication = "0".getBytes();
            dos.writeInt(indication.length);
            dos.write(indication);
            dos.writeInt(ephemeralUserID.length);
            dos.write(ephemeralUserID);
            dos.writeInt(gcmKey.length);
            dos.write(gcmKey);
            dos.flush();
        }
    }

    /**
     * send username to outer FIDO server.
     * Connect to FIDO server which is intialized outside of the sdk library.
     * Not best practice, but enough for PoC implementation.
     *
     * @throws IOException incase something happens
     * @throws InterruptedException incase something happens
     * */
    public void sendUsername() throws IOException, InterruptedException {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(new String[] {"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"});
        SocketFactory factory = SSLSocketFactory.getDefault();

        try (SSLSocket socket = (SSLSocket) factory.createSocket(hostname, fidoPort)) {
            System.out.println("TLS Server: Send username to FIDO Server");
            socket.setSSLParameters(params);

            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));

            byte[] uname_indication = "1".getBytes();
            dos.writeInt(uname_indication.length);
            dos.write(uname_indication);
            dos.writeInt(indication.getBytes().length);
            dos.write(indication.getBytes());
            dos.writeInt(username.getBytes().length);
            dos.write(username.getBytes());
            dos.flush();
        }
    }

    /**
     * get credential options from outer FIDO server.
     * Connect to FIDO server which is intialized outside of the sdk library.
     * Not best practice, but enough for PoC implementation.
     *
     * @throws IOException incase something happens
     * @throws InterruptedException incase something happens
     * @throws ClassNotFoundException incase somehting happens
     * */
    public void receiveCredOptions() throws IOException, InterruptedException, ClassNotFoundException {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(new String[] {"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"});
        SocketFactory factory = SSLSocketFactory.getDefault();

        try (SSLSocket socket = (SSLSocket) factory.createSocket(hostname, fidoPort)) {
            System.out.println("TLS Server: Ask FIDO Server for PublicKeyCredentialCreationOptions");
            socket.setSSLParameters(params);

            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));

            byte[] indication = "2".getBytes();
            dos.writeInt(indication.length);
            dos.write(indication);
            dos.flush();

            DataInputStream dis = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            int len = dis.readInt();
            options = dis.readNBytes(len);
        }
    }

    /**
     * Send response from ctap2 server to fido server.
     * Connect to FIDO server which is intialized outside of the sdk library.
     * Not best practice, but enough for PoC implementation.
     *
     * @throws IOException incase something happens
     * @throws InterruptedException incase something happens
     * */
    public void sendResponseToClient() throws IOException, InterruptedException {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(new String[] {"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"});
        SocketFactory factory = SSLSocketFactory.getDefault();

        try (SSLSocket socket = (SSLSocket) factory.createSocket(hostname, fidoPort)) {
            System.out.println("TLS Server: Sending response data to FIDO Server");
            socket.setSSLParameters(params);

            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));

            dos.writeInt(indication.getBytes().length);
            dos.write(indication.getBytes());
            dos.writeInt(response.length);
            dos.write(response);
            dos.flush();

            DataInputStream dis = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            int len = dis.readInt();
            byte[] succeed = dis.readNBytes(len);
        }
    }

    /**
     * get ephemeralUserID from outer FIDO server.
     * Connect to FIDO server which is intialized outside of the sdk library.
     * Not best practice, but enough for PoC implementation.
     *
     * @throws IOException incase something happens
     * @throws InterruptedException incase something happens
     * */
    public void receiveEphemeralUserIDAndGcmKey() throws IOException, InterruptedException {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(new String[] {"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"});
        SocketFactory factory = SSLSocketFactory.getDefault();

        try (SSLSocket socket = (SSLSocket) factory.createSocket(hostname, fidoPort)) {
            System.out.println("TLS Server: Ask CTAP2 Server for ephemeralUserID");
            socket.setSSLParameters(params);

            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));

            byte[] indication = "4".getBytes();
            dos.writeInt(indication.length);
            dos.write(indication);
            dos.flush();

            DataInputStream dis = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            int len = dis.readInt();
            ephemeralUserID = dis.readNBytes(len);

            len = dis.readInt();
            gcmKey = dis.readNBytes(len);
        }
    }

    /**
     * get request options from outer FIDO server.
     * Connect to FIDO server which is intialized outside of the sdk library.
     * Not best practice, but enough for PoC implementation.
     *
     * @throws IOException incase something happens
     * @throws InterruptedException incase something happens
     * @throws ClassNotFoundException incase somehting happens
     * */
    public void receiveReqOptions() throws IOException, InterruptedException, ClassNotFoundException {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(new String[] {"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"});
        SocketFactory factory = SSLSocketFactory.getDefault();

        try (SSLSocket socket = (SSLSocket) factory.createSocket(hostname, fidoPort)) {
            System.out.println("TLS Server: Ask FIDO Server for PublicKeyCredentialRequestOptions");
            socket.setSSLParameters(params);

            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));

            byte[] indication = "5".getBytes();
            dos.writeInt(indication.length);
            dos.write(indication);
            dos.flush();

            DataInputStream dis = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            int len = dis.readInt();
            options = dis.readNBytes(len);
        }
    }

    /**
     *
     * set response given by fido server
     *
     * @param response given by ctap2 server
     * */
    public void setResponse(byte[] response) {
        this.response = response;
    }

    /**
     *
     * get username by fido server
     *
     * @return username by fido server
     * */
    public String getUsername() {
        return username;
    }

    /**
     *
     * set ephemeralUserID by tls server
     *
     * @param ephemeralUserID by tls server
     * */
    public void setEphemeralUserID(byte[] ephemeralUserID) {
        this.ephemeralUserID = ephemeralUserID;
    }

    /**
     *
     * get ephemeralUserID by fido server
     *
     * @return ephemeralUserID by fido server
     * */
    public byte[] getEphemeralUserID() {
        return ephemeralUserID;
    }

    /**
     *
     * get Options
     *
     * @return options as byte[]
     * */
    public byte[] getOptions() {
        return options;
    }

    /**
     *
     * set gmcKey by tls server
     *
     * @param gmcKey by tls server
     * */
    public void setGcmKey(byte[] gmcKey) {
        this.gcmKey = gcmKey;
    }

    /**
     *
     * get gmcKey by fido server
     *
     * @return gmcKey by fido server
     * */
    public byte[] getGcmKey() {
        return gcmKey;
    }
}