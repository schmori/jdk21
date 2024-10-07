package javax.net.ssl;

import javax.net.SocketFactory;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

import java.nio.ByteBuffer;

/**
 * This class acts as ctap2 socket.
 */
public class CTAP2 {

    private int ctap2Port = 5555;
    private String hostname = "localhost";
    private String rpID;
    private byte[] response;
    private byte[] ephemeralUserID;
    private byte[] gcmMasterKey;
    private byte[] data;

    /**
     * Get all needed parameters for authentication.
     *
     * @param data given by tls server
     * */
    public CTAP2(byte[] data) {
        this.data = data;
    }

    /**
     * Empty Constructor
     *
     * */
    public CTAP2() {

    }

    /**
     * send ephemeralUserID to outer CTAP2 server.
     * Connect to CTAP2 server which is intialized outside of the sdk library.
     * Not best practice, but enough for PoC implementation.
     *
     * @throws IOException incase something happens
     * @throws InterruptedException incase something happens
     * */
    public void sendEphemeralUserIDAndGcmKey() throws IOException, InterruptedException {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(new String[] {"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"});
        SocketFactory factory = SSLSocketFactory.getDefault();

        try (SSLSocket socket = (SSLSocket) factory.createSocket(hostname, ctap2Port)) {
            System.out.println("Send username to CTAP2 Server");
            socket.setSSLParameters(params);

            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));

            byte[] indication = "0".getBytes();
            dos.writeInt(indication.length);
            dos.write(indication);
            dos.writeInt(ephemeralUserID.length);
            dos.write(ephemeralUserID);
            dos.writeInt(gcmMasterKey.length);
            dos.write(gcmMasterKey);
            dos.flush();
        }
    }

    /**
     * Get registration response of fido token.
     * Connect to CTAP2 server which is intialized outside of the sdk library.
     * Not best practice, but enough for PoC implementation.
     *
     * @throws IOException incase something happens
     * @throws InterruptedException incase something happens
     * */
    public void getClientRegResponse() throws IOException, InterruptedException {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(new String[] {"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"});
        SocketFactory factory = SSLSocketFactory.getDefault();

        try (SSLSocket socket = (SSLSocket) factory.createSocket(hostname, ctap2Port)) {
            System.out.println("Sending Response to CTAP2 client");
            socket.setSSLParameters(params);

            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));

            byte[] indication = "1".getBytes();
            dos.writeInt(indication.length);
            dos.write(indication);
            dos.writeInt(data.length);
            dos.write(data);
            dos.flush();

            DataInputStream dis = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            int response_len = dis.readInt();
            this.response = dis.readNBytes(response_len); // response = clientDataJosn + attestationResponse
        }
    }

    /**
     * get ephemeralUserID from outer CTAP2 server.
     * Connect to CTAP2 server which is intialized outside of the sdk library.
     * Not best practice, but enough for PoC implementation.
     *
     * @throws IOException incase something happens
     * @throws InterruptedException incase something happens
     * */
    public void receiveEphemeralUserIDAndGcmKey() throws IOException, InterruptedException {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(new String[] {"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"});
        SocketFactory factory = SSLSocketFactory.getDefault();

        try (SSLSocket socket = (SSLSocket) factory.createSocket(hostname, ctap2Port)) {
            System.out.println("Aks CTAP2 Server for ephemeralUserID");
            socket.setSSLParameters(params);

            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));

            byte[] indication = "2".getBytes();
            dos.writeInt(indication.length);
            dos.write(indication);
            dos.flush();

            DataInputStream dis = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            int len = dis.readInt();
            this.ephemeralUserID = dis.readNBytes(len);

            len = dis.readInt();
            this.gcmMasterKey = dis.readNBytes(len);
        }
    }

    /**
     * Get authentication response of fido token.
     * Connect to CTAP2 server which is intialized outside of the sdk library.
     * Not best practice, but enough for PoC implementation.
     *
     * @throws IOException incase something happens
     * @throws InterruptedException incase something happens
     * */
    public void getClientAuthResponse() throws IOException, InterruptedException {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(new String[] {"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"});
        SocketFactory factory = SSLSocketFactory.getDefault();

        try (SSLSocket socket = (SSLSocket) factory.createSocket(hostname, ctap2Port)) {
            System.out.println("Sending Response to CTAP2 client");
            socket.setSSLParameters(params);

            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));

            byte[] indication = "3".getBytes();
            dos.writeInt(indication.length);
            dos.write(indication);
            dos.writeInt(data.length);
            dos.write(data);
            dos.flush();

            DataInputStream dis = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            int response_len = dis.readInt();
            this.response = dis.readNBytes(response_len); // response = clientDataJosn + authenticator data + signature
        }
    }


    /**
     *
     * get response given by ctap2 server
     *
     * @return response given by fido client
     * */
    public byte[] getResponse() {
        return response;
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
     * get ephemeralUserID given by ctap2 server
     *
     * @return ephemeralUserID given by ctap2 client
     * */
    public byte[] getEphemeralUserID() {
        return ephemeralUserID;
    }

    /**
     *
     * set gcmMasterKey by tls server
     *
     * @param gcmMasterKey by tls server
     * */
    public void setGcmMasterKey(byte[] gcmMasterKey) {
        this.gcmMasterKey = gcmMasterKey;
    }

    /**
     *
     * get gcmMasterKey given by ctap2 server
     *
     * @return gcmMasterKey given by ctap2 client
     * */
    public byte[] getGcmMasterKey() {
        return gcmMasterKey;
    }
}