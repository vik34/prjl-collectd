package prjl.collectd;

import com.sun.istack.internal.NotNull;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.concurrent.Callable;

public class CollectdTimer {

  protected CollectdProxy.CollectdGaugeProxy mCollectdGaugeProxy;

  protected Instant mStart;
  protected Instant mStop;

  public CollectdTimer(@NotNull CollectdProxy.CollectdGaugeProxy collectd_gauge_proxy) {
    mCollectdGaugeProxy = collectd_gauge_proxy;
  }

  @NotNull
  public <T> T time(@NotNull Callable<T> callable) throws Exception {
    try {
      start();
      return callable.call();
    } catch(Exception e) {
      throw e;
    } finally {
      stop();
      send();
    }
  }

  @NotNull
  public CollectdTimer time(@NotNull Runnable runnable) throws Exception {
    try {
      start();
      runnable.run();
    } catch(Exception e) {
      throw e;
    } finally {
      stop();
      send();
    }

    return this;
  }

  private Instant now() {
    return Instant.now(Clock.system(ZoneId.systemDefault()));
  }

  @NotNull
  public CollectdTimer start() {
    mStart = now();

    return this;
  }

  @NotNull
  public CollectdTimer stop() {
    mStop = now();

    return this;
  }

  @NotNull
  public CollectdTimer send() throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    double delta = mStop.toEpochMilli() - mStart.toEpochMilli();

    getCollectdGaugeProxy().send(delta);

    return this;
  }

  @NotNull
  public CollectdProxy.CollectdGaugeProxy getCollectdGaugeProxy() {
    return mCollectdGaugeProxy;
  }
}