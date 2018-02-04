package prjl.collectd;

import com.sun.istack.internal.NotNull;
import com.sun.istack.internal.Nullable;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.function.Function;

/**
 * @see "https://collectd.org/wiki/index.php/Binary_protocol"
 * @see prjl.collectd.CollectdTimer
 */
public class Collectd implements AutoCloseable {

  public static final int TYPE_HOST            = 0x0000;
  public static final int TYPE_TIME            = 0x0001;
  public static final int TYPE_TIME_HR         = 0x0008;
  public static final int TYPE_PLUGIN          = 0x0002;
  public static final int TYPE_PLUGIN_INSTANCE = 0x0003;
  public static final int TYPE_TYPE            = 0x0004;
  public static final int TYPE_TYPE_INSTANCE   = 0x0005;
  public static final int TYPE_VALUES          = 0x0006;
  public static final int TYPE_INTERVAL        = 0x0007;
  public static final int TYPE_INTERVAL_HR     = 0x0009;
  public static final int TYPE_MESSAGE         = 0x0100;
  public static final int TYPE_SEVERITY        = 0x0101;
  public static final int TYPE_SIGN_SHA256     = 0x0200;
  public static final int TYPE_ENCR_AES256     = 0x0210;

  public static final byte TYPE_VALUE_COUNTER  = 0x0;
  public static final byte TYPE_VALUE_GAUGE    = 0x1;
  public static final byte TYPE_VALUE_DERIVE   = 0x2;
  public static final byte TYPE_VALUE_ABSOLUTE = 0x4;

  public static final int SECURITY_LEVEL_NONE    = 0x0;
  public static final int SECURITY_LEVEL_SIGN    = 0x1;
  public static final int SECURITY_LEVEL_ENCRYPT = 0x2;

  protected String mEndpointHostname;
  protected short mEndpointPort = 25826;

  protected String mHostname;
  protected short mPort = 25826;

  protected String mUsername;
  protected String mPassword;

  protected int mSecurityLevel = SECURITY_LEVEL_ENCRYPT;

  protected DatagramSocket mSocket;

  protected int mBufferSize = 1024;

  public Collectd() {
    try {
      setHostname(InetAddress.getLocalHost().getCanonicalHostName());
    } catch(UnknownHostException e) {
      e.printStackTrace();
    }
  }

  @NotNull
  public CollectdProxy.CollectdCounterProxy getCounterProxy() {
    return new CollectdProxy.CollectdCounterProxy().setCollectd(this);
  }

  @NotNull
  public CollectdProxy.CollectdGaugeProxy getGaugeProxy() {
    return new CollectdProxy.CollectdGaugeProxy().setCollectd(this);
  }

  @NotNull
  public CollectdProxy.CollectdDeriveProxy getDeriveProxy() {
    return new CollectdProxy.CollectdDeriveProxy().setCollectd(this);
  }

  @NotNull
  public CollectdProxy.CollectdAbsoluteProxy getAbsoluteProxy() {
    return new CollectdProxy.CollectdAbsoluteProxy().setCollectd(this);
  }

  @NotNull
  public Collectd send(@NotNull List<CollectdPart> parts) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    for(CollectdPart part : parts) {
      baos.write(part.getBytes());
    }

    byte[] bytes          = baos.toByteArray();
    int    security_level = getSecurityLevel();

    switch(security_level) {
      case SECURITY_LEVEL_SIGN: {
        bytes = new CollectdPart.SignaturePart(bytes, getUsername(), getPassword()).getBytes();
        break;
      }

      case SECURITY_LEVEL_ENCRYPT: {
        bytes = new CollectdPart.EncryptPart(bytes, getUsername(), getPassword()).getBytes();
        break;
      }

      case SECURITY_LEVEL_NONE:
      default: {

      }
    }

    return send(bytes);
  }

  @NotNull
  public Collectd send(@NotNull byte[] bytes) throws IOException {
    InetAddress inet_address = InetAddress.getByName(getEndpointHostname());

    DatagramPacket datagram_packet = new DatagramPacket(bytes, bytes.length, inet_address, getEndpointPort());

    mSocket.send(datagram_packet);

    return this;
  }

  @NotNull
  public Collectd recv(@NotNull List<CollectdPart> part_list_dest, Function<byte[], byte[]> on_crypto) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    recv(baos);

    byte[] data = baos.toByteArray();
    CollectdPart.parse(data, part_list_dest, on_crypto);

    return this;
  }

  @NotNull
  public Collectd recv(@NotNull OutputStream os) throws IOException {
    byte[] buffer = new byte[getBufferSize()];

    DatagramPacket datagram_packet = new DatagramPacket(buffer, buffer.length);

    mSocket.receive(datagram_packet);

    byte[] data = new byte[datagram_packet.getLength()];

    System.arraycopy(datagram_packet.getData(), 0, data, 0, data.length);

    os.write(data);

    return this;
  }

  @NotNull
  public Collectd bind() throws SocketException, UnknownHostException {
    InetAddress inet_addr = InetAddress.getByName(getHostname());

    mSocket = new DatagramSocket(getPort(), inet_addr);

    return this;
  }

  @NotNull
  public Collectd connect() throws SocketException {
    mSocket = new DatagramSocket();

    return this;
  }

  public void close() {
    if(mSocket != null && mSocket.isConnected()) {
      mSocket.close();
    }

    mSocket = null;
  }

  public int getSecurityLevel() {
    return mSecurityLevel;
  }

  @NotNull
  public Collectd setSecurityLevel(int security_level) {
    mSecurityLevel = security_level;

    return this;
  }

  @Nullable
  public String getHostname() {
    return mHostname;
  }

  @NotNull
  public Collectd setHostname(@NotNull String hostname) {
    mHostname = hostname;

    return this;
  }

  @Nullable
  public String getPassword() {
    return mPassword;
  }

  @NotNull
  public Collectd setPassword(@NotNull String password) {
    mPassword = password;

    return this;
  }

  @Nullable
  public String getUsername() {
    return mUsername;
  }

  @NotNull
  public Collectd setUsername(@NotNull String username) {
    mUsername = username;

    return this;
  }

  @Nullable
  public String getEndpointHostname() {
    return mEndpointHostname;
  }

  @NotNull
  public Collectd setEndpointHostname(@NotNull String endpoint_hostname) {
    mEndpointHostname = endpoint_hostname;

    return this;
  }

  @NotNull
  public Collectd setEndpointPort(int endpoint_port) {
    return setEndpointPort((short) endpoint_port);
  }

  public int getEndpointPort() {
    return mEndpointPort;
  }

  @NotNull
  public Collectd setEndpointPort(short endpoint_port) {
    mEndpointPort = endpoint_port;

    return this;
  }

  @NotNull
  public Collectd setPort(int port) {
    return setPort((short) port);
  }

  public int getPort() {
    return mPort;
  }

  @NotNull
  public Collectd setPort(short port) {
    mPort = port;

    return this;
  }

  @NotNull
  public int getBufferSize() {
    return mBufferSize;
  }

  @NotNull
  public Collectd setBufferSize(int buffer_size) {
    mBufferSize = buffer_size;

    return this;
  }
}