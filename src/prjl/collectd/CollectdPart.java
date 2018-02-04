package prjl.collectd;

import com.sun.istack.internal.NotNull;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.InputMismatchException;
import java.util.List;
import java.util.function.Function;

/**
 * uint16_t  type
 * uint16_t  size =   sizeof type
 *                  + sizeof size
 *                  + sizeof data
 * uint8_t[] data
 * */
public class CollectdPart {
  public static final short HEADER_BYTES = Short.BYTES + Short.BYTES;

  private static final byte[] NO_BYTES = new byte[0];

  public static String CHARSET_NAME = "UTF-8";

  protected short mType;
  protected short mSize;
  protected byte[] mData = NO_BYTES;

  public CollectdPart() {

  }

  public CollectdPart(int type, int size, @NotNull byte[] data) {
    this();
    setType(type);
    setSize(size);
    setData(data);
  }

  public CollectdPart(int type, @NotNull byte[] data) {
    this(type, data.length, data);
  }

  public CollectdPart(int type) {
    setType(type);
  }

  @NotNull
  public static void parse(@NotNull byte[] bytes, @NotNull List<CollectdPart> part_list_dest) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    parse(bytes, part_list_dest, username_bytes -> new byte[0]);
  }

  @NotNull
  public static void parse(@NotNull byte[] bytes, @NotNull List<CollectdPart> part_list_dest, @NotNull Function<byte[], byte[]> on_crypto) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    ByteBuffer byte_buffer = ByteBuffer.wrap(bytes);

    while(byte_buffer.remaining() > 0) {
      int type = byte_buffer.getShort();
      int size = byte_buffer.getShort();

      switch(type) {
        case Collectd.TYPE_SIGN_SHA256: {
          byte[] data = CollectdPart.SignaturePart.verify(bytes, on_crypto);
          parse(data, part_list_dest, on_crypto);
          return;
        }

        case Collectd.TYPE_ENCR_AES256: {
          byte[] data = CollectdPart.EncryptPart.decrypt(bytes, on_crypto);
          parse(data, part_list_dest, on_crypto);
          return;
        }

        case Collectd.TYPE_HOST: {
          byte[] data = new byte[size - Short.BYTES - Short.BYTES];
          byte_buffer.get(data);
          part_list_dest.add(new CollectdPart.HostPart(data));
          break;
        }

        case Collectd.TYPE_TIME: {
          byte[] data = new byte[size - Short.BYTES - Short.BYTES];
          byte_buffer.get(data);
          part_list_dest.add(new CollectdPart.TimePart(data));
          break;
        }

        case Collectd.TYPE_PLUGIN: {
          byte[] data = new byte[size - Short.BYTES - Short.BYTES];
          byte_buffer.get(data);
          part_list_dest.add(new CollectdPart.PluginPart(data));
          break;
        }

        case Collectd.TYPE_PLUGIN_INSTANCE: {
          byte[] data = new byte[size - Short.BYTES - Short.BYTES];
          byte_buffer.get(data);
          part_list_dest.add(new CollectdPart.PluginInstancePart(data));
          break;
        }

        case Collectd.TYPE_TYPE: {
          byte[] data = new byte[size - Short.BYTES - Short.BYTES];
          byte_buffer.get(data);
          part_list_dest.add(new CollectdPart.TypePart(data));
          break;
        }

        case Collectd.TYPE_TYPE_INSTANCE: {
          byte[] data = new byte[size - Short.BYTES - Short.BYTES];
          byte_buffer.get(data);
          part_list_dest.add(new CollectdPart.TypeInstancePart(data));
          break;
        }

        case Collectd.TYPE_VALUES: {
          byte[] data = new byte[size - Short.BYTES - Short.BYTES];
          byte_buffer.get(data);
          part_list_dest.add(new CollectdPart.ValuePart(data));
          break;
        }

        default: {
          byte[] data = new byte[size - Short.BYTES - Short.BYTES];
          byte_buffer.get(data);
          part_list_dest.add(new CollectdPart(type, size, data));
        }
      }
    }
  }

  public int getType() {
    return mType;
  }

  public CollectdPart setType(int type) {
    mType = (short) type;

    return this;
  }

  public int getSize() {
    return mSize;
  }

  @NotNull
  public CollectdPart setSize(int size) {
    mSize = (short) size;

    return this;
  }

  @NotNull
  public byte[] getData() {
    return mData;
  }

  public CollectdPart setData(@NotNull byte[] data) {
    mData = data;

    return this;
  }

  @NotNull
  public byte[] getBytes() {
    return ByteBuffer
        .allocate(HEADER_BYTES + mData.length)
        .order(ByteOrder.BIG_ENDIAN)
        .putShort(mType)
        .putShort((short) (HEADER_BYTES + mSize))
        .put(mData)
        .array();
  }

  public static class HostPart extends StringPart {
    public HostPart(@NotNull byte[] hostname) {
      super(Collectd.TYPE_HOST, hostname);
    }

    public HostPart(@NotNull String hostname) throws UnsupportedEncodingException {
      super(Collectd.TYPE_HOST, hostname);
    }
  }

  public static class PluginPart extends StringPart {
    public PluginPart(@NotNull byte[] plugin_name) {
      super(Collectd.TYPE_PLUGIN, plugin_name);
    }

    public PluginPart(@NotNull String plugin_name) throws UnsupportedEncodingException {
      super(Collectd.TYPE_PLUGIN, plugin_name);
    }
  }

  public static class PluginInstancePart extends StringPart {
    public PluginInstancePart(@NotNull byte[] plugin_instance) {
      super(Collectd.TYPE_PLUGIN_INSTANCE, plugin_instance);
    }

    public PluginInstancePart(@NotNull String plugin_instance) throws UnsupportedEncodingException {
      super(Collectd.TYPE_PLUGIN_INSTANCE, plugin_instance);
    }
  }

  public static class TypePart extends StringPart {
    public TypePart(@NotNull byte[] type) {
      super(Collectd.TYPE_TYPE, type);
    }

    public TypePart(@NotNull String type) throws UnsupportedEncodingException {
      super(Collectd.TYPE_TYPE, type);
    }
  }

  public static class TypeInstancePart extends ValuePart.StringPart {
    public TypeInstancePart(@NotNull byte[] type) {
      super(Collectd.TYPE_TYPE_INSTANCE, type);
    }

    public TypeInstancePart(@NotNull String type) throws UnsupportedEncodingException {
      super(Collectd.TYPE_TYPE_INSTANCE, type);
    }
  }

  public static class TimePart extends CollectdPart {
    public TimePart(@NotNull byte[] time_bytes) {
      super(Collectd.TYPE_TIME);

      setData(time_bytes);
      setSize(time_bytes.length);
    }

    public TimePart(long time) {
      super(Collectd.TYPE_TIME);

      byte[] bytes = ByteBuffer
          .allocate(Long.BYTES)
          .order(ByteOrder.BIG_ENDIAN)
          .putLong(time)
          .array();

      setData(bytes);
      setSize(bytes.length);
    }

    public long getTime() {
      return ByteBuffer.wrap(mData).getLong();
    }
  }

  /**
   * uint16_t    type = 0x0200
   * uint16_t    size =   sizeof type
   *                    + sizeof size
   *                    + sizeof hmac_sha256
   *                    + sizeof username_bytes
   * uint8_t[32] hmac_sha256
   * uint8_t[]   username_bytes
   * uint8_t[]   data
   *
   * @see prjl.collectd.CollectdCrypto#getHMAC(byte[])
   * */
  public static class SignaturePart extends CollectdPart {

    public static final int HMAC_SHA256_BYTES = 32;

    public SignaturePart(@NotNull byte[] data, @NotNull String username, @NotNull String password) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
      this(data, username.getBytes(CHARSET_NAME), password.getBytes(CHARSET_NAME));
    }

    public SignaturePart(@NotNull byte[] data, @NotNull byte[] username_bytes, @NotNull byte[] password_bytes) throws NoSuchAlgorithmException, InvalidKeyException {
      super(Collectd.TYPE_SIGN_SHA256);

      setSize(username_bytes.length + HMAC_SHA256_BYTES);

      byte[] data_signed = sign(data, username_bytes, password_bytes);
      setData(data_signed);
    }

    @NotNull
    public static byte[] sign(@NotNull byte[] bytes, @NotNull byte[] username_bytes, @NotNull byte[] password_bytes) throws NoSuchAlgorithmException, InvalidKeyException {
      Mac hmac_sha256 = CollectdCrypto.getHMAC(password_bytes);

      hmac_sha256.update(username_bytes);
      hmac_sha256.update(bytes);

      byte[] bytes_digest_hmac_sha256 = hmac_sha256.doFinal();

      return ByteBuffer
          .allocate(
              bytes_digest_hmac_sha256.length
                  + username_bytes.length
                  + bytes.length
          )
          .put(bytes_digest_hmac_sha256)
          .put(username_bytes)
          .put(bytes)
          .array();
    }

    @NotNull
    public static byte[] verify(@NotNull byte[] bytes, @NotNull Function<byte[], byte[]> on_crypto) throws NoSuchAlgorithmException, InvalidKeyException, InputMismatchException {
      ByteBuffer byte_buffer = ByteBuffer.wrap(bytes);

      int type = byte_buffer.getShort();
      int size = byte_buffer.getShort();

      byte[] data_digest_hmac_sha256 = new byte[HMAC_SHA256_BYTES];
      byte_buffer.get(data_digest_hmac_sha256);

      short  username_size  = (short) (size - Short.BYTES - Short.BYTES - data_digest_hmac_sha256.length);
      byte[] username_bytes = new byte[username_size];
      byte_buffer.get(username_bytes);

      byte[] data = new byte[byte_buffer.remaining()];
      byte_buffer.get(data);

      byte[] password_bytes = on_crypto.apply(username_bytes);
      Mac    hmac_sha256    = CollectdCrypto.getHMAC(password_bytes);

      hmac_sha256.update(username_bytes);
      hmac_sha256.update(data);
      byte[] bytes_digest_hmac_sha256 = hmac_sha256.doFinal();

      if(!Arrays.equals(data_digest_hmac_sha256, bytes_digest_hmac_sha256)) {
        throw new InputMismatchException("Invalid Checksum.");
      }

      return data;
    }
  }

  /**
   * uint16_t    type          = 0x0210
   * uint16_t    size          =   sizeof type
   *                             + sizeof size
   *                             + sizeof username_size
   *                             + sizeof username
   *                             + sizeof iv
   *                             + sizeof data_sha1_encrypted
   *                             + sizeof data_encrypted
   * uint16_t    username_size = sizeof username
   * uint8_t[]   username
   * uint8_t[16] iv
   * uint8_t[20] data_sha1_encrypted
   * uint8_t[]   data_encrypted
   *
   * @see prjl.collectd.CollectdCrypto#getIvParameterSpec()
   * @see prjl.collectd.CollectdCrypto#getEncryptCipher(javax.crypto.spec.IvParameterSpec, byte[])
   * */
  public static class EncryptPart extends CollectdPart {
    public EncryptPart(@NotNull byte[] bytes, @NotNull String username, @NotNull String password) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
      this(bytes, username.getBytes(CHARSET_NAME), password.getBytes(CHARSET_NAME));
    }

    public EncryptPart(@NotNull byte[] bytes, @NotNull byte[] username_bytes, @NotNull byte[] password_bytes) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
      super(Collectd.TYPE_ENCR_AES256);

      byte[] bytes_encrypted = encrypt(bytes, username_bytes, password_bytes);
      setData(bytes_encrypted);

      setSize(bytes_encrypted.length);
    }

    @NotNull
    public static byte[] encrypt(@NotNull byte[] bytes, @NotNull byte[] username_bytes, @NotNull byte[] password_bytes) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
      MessageDigest   message_digest_sha1 = MessageDigest.getInstance("SHA1");
      IvParameterSpec iv_parameter_spec   = CollectdCrypto.getIvParameterSpec();
      Cipher          cipher              = CollectdCrypto.getEncryptCipher(iv_parameter_spec, password_bytes);

      short  username_size               = (short) username_bytes.length;
      byte[] iv_parameter_spec_bytes     = iv_parameter_spec.getIV();
      byte[] bytes_digest_sha1           = message_digest_sha1.digest(bytes);
      byte[] bytes_digest_sha1_encrypted = cipher.update(bytes_digest_sha1);
      byte[] bytes_encrypted             = cipher.doFinal(bytes);

      return ByteBuffer
          .allocate(
              Short.BYTES
                  + username_bytes.length
                  + iv_parameter_spec_bytes.length
                  + bytes_digest_sha1_encrypted.length
                  + bytes_encrypted.length
          )
          .order(ByteOrder.BIG_ENDIAN)
          .putShort(username_size)
          .put(username_bytes)
          .put(iv_parameter_spec_bytes)
          .put(bytes_digest_sha1_encrypted)
          .put(bytes_encrypted)
          .array();
    }

    @NotNull
    public static byte[] decrypt(@NotNull byte[] bytes, Function<byte[], byte[]> on_crypto) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
      ByteBuffer byte_buffer = ByteBuffer.wrap(bytes);

      short type          = byte_buffer.getShort();
      short size          = byte_buffer.getShort();
      short username_size = byte_buffer.getShort();

      byte[] username_bytes          = new byte[username_size];
      byte[] data_digest_sha1        = new byte[20];
      byte[] iv_parameter_spec_bytes = new byte[16];
      byte[] data_encrypted          = new byte[byte_buffer.remaining() - username_size - iv_parameter_spec_bytes.length];
      byte[] data                    = new byte[data_encrypted.length - data_digest_sha1.length];

      byte_buffer.get(username_bytes);
      byte_buffer.get(iv_parameter_spec_bytes);
      IvParameterSpec iv_parameter_spec = new IvParameterSpec(iv_parameter_spec_bytes);

      byte[] password_bytes = on_crypto.apply(username_bytes);
      Cipher cipher         = CollectdCrypto.getDecryptCipher(iv_parameter_spec, password_bytes);

      byte_buffer.get(data_encrypted);

      byte[] data_decrypted = cipher.doFinal(data_encrypted);
      byte_buffer = ByteBuffer.wrap(data_decrypted);
      byte_buffer.get(data_digest_sha1);
      byte_buffer.get(data);

      MessageDigest message_digest_sha1 = MessageDigest.getInstance("SHA1");
      byte[]        bytes_digest_sha1   = message_digest_sha1.digest(data);

      if(!Arrays.equals(data_digest_sha1, bytes_digest_sha1)) {
        throw new InputMismatchException("Checksum mismatch.");
      }

      return data;
    }
  }

  public static class CounterValuePart extends ValuePart {
    public CounterValuePart(long value) {
      super(Collectd.TYPE_VALUE_COUNTER, value);
    }
  }

  public static class GaugeValuePart extends ValuePart {
    public GaugeValuePart(double value) {
      super(value);
    }
  }

  public static class DeriveValuePart extends ValuePart {
    public DeriveValuePart(long value) {
      super(Collectd.TYPE_VALUE_DERIVE, value);
    }
  }

  public static class AbsoluteValuePart extends ValuePart {
    public AbsoluteValuePart(long value) {
      super(Collectd.TYPE_VALUE_ABSOLUTE, value);
    }
  }

  /**
   * uint16_t type         = 0x0006
   * uint16_t size         =   sizeof type
   *                         + sizeof size
   *                         +        size
   * uint16_t values_count = 1
   * uint8_t  data_type    = long   COUNTER  = 0
   *                         double GAUGE    = 1
   *                         long   DERIVE   = 2
   *                         long   ABSOLUTE = 3
   * uint64_t value        = double LITTLE_ENDIAN
   *                         long   BIG_ENDIAN
   */
  public static class ValuePart extends CollectdPart {
    public static final short VALUE_COUNT = 1;

    public ValuePart(@NotNull byte[] bytes) {
      this(Collectd.TYPE_VALUES);

      setData(bytes);
      setSize(bytes.length);
    }

    public ValuePart(byte value_type, long value) {
      super(Collectd.TYPE_VALUES);

      byte[] bytes = ByteBuffer
          .allocate(
              Short.BYTES
                  + Byte.BYTES
                  + Long.BYTES
          )
          .order(ByteOrder.BIG_ENDIAN)
          .putShort(VALUE_COUNT)
          .put(value_type)
          .order(ByteOrder.BIG_ENDIAN)
          .putLong(value)
          .array();

      setData(bytes);
      setSize(bytes.length);
    }

    public ValuePart(byte value_type, double value) {
      super(Collectd.TYPE_VALUES);

      byte[] bytes = ByteBuffer
          .allocate(
              Short.BYTES
                  + Byte.BYTES
                  + Double.BYTES
          )
          .order(ByteOrder.BIG_ENDIAN)
          .putShort(VALUE_COUNT)
          .put(value_type)
          .order(ByteOrder.LITTLE_ENDIAN)
          .putDouble(value)
          .array();

      setData(bytes);
      setSize(bytes.length);
    }

    public ValuePart(double value) {
      this(Collectd.TYPE_VALUE_GAUGE, value);
    }

    public short getValueCount() {
      return ByteBuffer.wrap(mData).getShort();
    }

    @NotNull
    public List getValues(byte value_type) {
      ByteBuffer byte_buffer = ByteBuffer.wrap(mData);

      int total_value_count = byte_buffer.getShort();

      boolean[] value_map = new boolean[total_value_count];

      for(short i = 0; i < total_value_count; ++i) {
        byte current_value_type = byte_buffer.get();
        if(current_value_type == value_type) {
          value_map[i] = true;
        }
      }

      ArrayList value_list = new ArrayList<>();

      for(short i = 0, j = 0; i < total_value_count; ++i) {
        if(value_map[i]) {
          if(value_type == Collectd.TYPE_VALUE_GAUGE) {
            value_list.add(byte_buffer.order(ByteOrder.LITTLE_ENDIAN).getDouble());
          } else {
            value_list.add(byte_buffer.order(ByteOrder.BIG_ENDIAN).getLong());
          }
        }
      }

      return value_list;
    }

    @NotNull
    public double[] getDoubleValues(byte value_type) {
      List<Double> double_list = getValues(value_type);

      double[] double_values = new double[double_list.size()];

      for(int i = 0; i < double_list.size(); ++i) {
        double_values[i] = double_list.get(i);
      }

      return double_values;
    }

    @NotNull
    public long[] getLongValues(byte value_type) {
      List<Long> long_list = getValues(value_type);

      long[] long_values = new long[long_list.size()];

      for(int i = 0; i < long_list.size(); ++i) {
        long_values[i] = long_list.get(i);
      }

      return long_values;
    }
  }

  /**
   * uint16_t  type
   * uint16_t  size =   sizeof type
   *                  + sizeof size
   *                  + sizeof data
   * uint8_t[] data
   */
  public static class StringPart extends CollectdPart {
    public StringPart(int type, @NotNull String string) throws UnsupportedEncodingException {
      this(type, string.getBytes(CHARSET_NAME));
    }

    public StringPart(int type, @NotNull byte[] bytes) {
      super(type);

      setString(bytes);
    }

    @NotNull
    public StringPart setString(@NotNull String string) throws UnsupportedEncodingException {
      return setString(string.getBytes(CHARSET_NAME));
    }

    @NotNull
    public String getString() throws UnsupportedEncodingException {
      return new String(mData, 0, mData.length - 1, CHARSET_NAME);
    }

    @NotNull
    public StringPart setString(@NotNull byte[] bytes) {
      if(bytes.length == 0 || bytes[bytes.length - 1] != '\0') {
        bytes = ByteBuffer
            .allocate(bytes.length + 1)
            .put(bytes)
            .put((byte) '\0')
            .array();
      }

      setData(bytes);
      setSize(bytes.length);

      return this;
    }
  }
}