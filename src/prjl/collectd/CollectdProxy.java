package prjl.collectd;

import com.sun.istack.internal.NotNull;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;

public abstract class CollectdProxy<T, S extends CollectdProxy<T, ?>> {

  protected Collectd mCollectd;

  protected String mPlugin         = "";
  protected String mPluginInstance = "";
  protected String mType           = "";
  protected String mTypePart       = "";

  public CollectdProxy() {

  }

  @NotNull
  protected abstract CollectdPart.ValuePart getValuePart(@NotNull T value) throws IOException;

  @NotNull
  public S send(@NotNull T value) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    return send(Instant.now().getEpochSecond(), value);
  }

  @NotNull
  public S send(long time, @NotNull T value) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    getCollectd().send(new ArrayList<CollectdPart>() {{
      add(new CollectdPart.HostPart(getCollectd().getHostname()));
      add(new CollectdPart.TimePart(time));
      add(new CollectdPart.PluginPart(getPlugin()));
      add(new CollectdPart.PluginInstancePart(getPluginInstance()));
      add(new CollectdPart.TypePart(getType()));
      add(new CollectdPart.TypeInstancePart(getTypePart()));
      add(getValuePart(value));
    }});

    return (S) this;
  }

  @NotNull
  public Collectd getCollectd() {
    return mCollectd;
  }

  @NotNull
  public S setCollectd(@NotNull Collectd collectd) {
    mCollectd = collectd;

    return (S) this;
  }

  @NotNull
  public String getPlugin() {
    return mPlugin;
  }

  @NotNull
  public S setPlugin(@NotNull String plugin) {
    mPlugin = plugin;

    return (S) this;
  }

  @NotNull
  public String getPluginInstance() {
    return mPluginInstance;
  }

  @NotNull
  public S setPluginInstance(@NotNull String plugin_instance) {
    mPluginInstance = plugin_instance;

    return (S) this;
  }

  @NotNull
  public String getType() {
    return mType;
  }

  @NotNull
  public S setType(@NotNull String type) {
    mType = type;

    return (S) this;
  }

  @NotNull
  public String getTypePart() {
    return mTypePart;
  }

  @NotNull
  public S setTypePart(@NotNull String type_part) {
    mTypePart = type_part;

    return (S) this;
  }

  public static class CollectdCounterProxy extends CollectdProxy<Long, CollectdCounterProxy> {

    protected String mType = "counter";

    @NotNull
    @Override
    protected CollectdPart.ValuePart getValuePart(@NotNull Long value) {
      return new CollectdPart.CounterValuePart(value);
    }
  }

  public static class CollectdGaugeProxy extends CollectdProxy<Double, CollectdGaugeProxy> {

    protected String mType = "gauge";

    @NotNull
    @Override
    protected CollectdPart.ValuePart getValuePart(@NotNull Double value) {
      return new CollectdPart.GaugeValuePart(value);
    }

    @NotNull
    public CollectdTimer getTimerProxy() {
      return new CollectdTimer(this);
    }
  }

  public static class CollectdDeriveProxy extends CollectdProxy<Long, CollectdDeriveProxy> {

    protected String mType = "derive";

    @NotNull
    @Override
    protected CollectdPart.ValuePart getValuePart(@NotNull Long value) {
      return new CollectdPart.DeriveValuePart(value);
    }
  }

  public static class CollectdAbsoluteProxy extends CollectdProxy<Long, CollectdAbsoluteProxy> {

    protected String mType = "absolute";

    @NotNull
    @Override
    protected CollectdPart.ValuePart getValuePart(@NotNull Long value) {
      return new CollectdPart.AbsoluteValuePart(value);
    }
  }
}