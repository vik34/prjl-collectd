package prjl.collectd;

import com.sun.istack.internal.NotNull;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class CollectdCrypto {

  private CollectdCrypto() {

  }

  @NotNull
  public static Cipher getCipher(int cipher_mode, @NotNull IvParameterSpec iv_parameter_spec, @NotNull byte[] password_bytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    SecretKeySpec secret_key_spec_aes256 = getSecretKeySpec(password_bytes);

    Cipher aes256_ofb_nopadding = Cipher.getInstance("AES/OFB/NoPadding");
    aes256_ofb_nopadding.init(cipher_mode, secret_key_spec_aes256, iv_parameter_spec);

    return aes256_ofb_nopadding;
  }

  @NotNull
  public static Cipher getEncryptCipher(@NotNull IvParameterSpec iv_parameter_spec, @NotNull byte[] password_bytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    return getCipher(Cipher.ENCRYPT_MODE, iv_parameter_spec, password_bytes);
  }

  @NotNull
  public static Cipher getDecryptCipher(@NotNull IvParameterSpec iv_parameter_spec, @NotNull byte[] password_bytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    return getCipher(Cipher.DECRYPT_MODE, iv_parameter_spec, password_bytes);
  }

  @NotNull
  public static SecretKeySpec getSecretKeySpec(@NotNull byte[] password_bytes) throws NoSuchAlgorithmException {
    MessageDigest message_digest_sha256 = MessageDigest.getInstance("SHA-256");

    byte password_digest_sha256[] = message_digest_sha256.digest(password_bytes);

    SecretKeySpec secret_key_spec_aes256 = new SecretKeySpec(password_digest_sha256, "AES");

    return secret_key_spec_aes256;
  }

  @NotNull
  public static IvParameterSpec getIvParameterSpec() {
    SecureRandom random                    = new SecureRandom();
    byte         iv_parameter_spec_bytes[] = new byte[16];

    random.nextBytes(iv_parameter_spec_bytes);
    IvParameterSpec iv_spec = new IvParameterSpec(iv_parameter_spec_bytes);

    return iv_spec;
  }

  @NotNull
  public static Mac getHMAC(@NotNull byte[] password_bytes) throws NoSuchAlgorithmException, InvalidKeyException {
    Mac           hmac_sha256                 = Mac.getInstance("HmacSHA256");
    SecretKeySpec secret_key_spec_hmac_sha256 = new SecretKeySpec(password_bytes, "HmacSHA256");

    hmac_sha256.init(secret_key_spec_hmac_sha256);

    return hmac_sha256;
  }
}