# Collectd

```java
import prjl.collectd.Collectd;
import prjl.collectd.CollectdPart;
import prjl.collectd.CollectdProxy;
import prjl.collectd.CollectdTimer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.function.Function;

public final class Example {
  public static final String HOSTNAME = "example.com";
  public static final String USERNAME = "example_user";
  public static final String PASSWORD = "example_password";

  public static final String HOSTNAME_ENDPOINT = "127.0.0.1";

  public static final String FORWARD_HOSTNAME_OVERWRITE = "another.example.com";
  public static final String FORWARD_USERNAME           = "different_example_user";
  public static final String FORWARD_PASSWORD           = "different_example_password";
  public static final String FORWARD_HOSTNAME_ENDPOINT  = "127.0.0.1";

  private static final Map<String, String> AUTH_DATA = new HashMap<String, String>() {{
    put(USERNAME, PASSWORD);
    put(FORWARD_USERNAME, FORWARD_PASSWORD);
  }};

  private static final Function<byte[], byte[]> ON_CRYPTO = (byte[] username_bytes) -> {
    try {
      return AUTH_DATA.get(new String(username_bytes)).getBytes(CollectdPart.CHARSET_NAME);
    } catch(Exception e) {
      e.printStackTrace();
    }

    return new byte[0];
  };

  public static void main(String args[]) throws Exception {
    Forwarder forwarder = new Forwarder();
    Receiver  receiver  = new Receiver();
    Sender    sender    = new Sender();

    forwarder.start();
    receiver.start();
    sender.start();

    forwarder.join();
    receiver.join();
    sender.join();
  }

  public static final class Receiver extends Thread {
    @Override
    public void run() {
      try {
        Collectd collectd = new Collectd()
            .setHostname(HOSTNAME_ENDPOINT)
            .setPort(25826 + 1)
            .bind();

        while(true) {
          ArrayList<CollectdPart> part_list = new ArrayList<>();
          collectd.recv(part_list, ON_CRYPTO);

          for(CollectdPart part : part_list) {
            if(part instanceof CollectdPart.HostPart) {
              CollectdPart.HostPart host_part = (CollectdPart.HostPart) part;
              System.out.println(host_part.getString());
            }

            if(part instanceof CollectdPart.ValuePart) {
              double[] values = ((CollectdPart.ValuePart) part).getDoubleValues(Collectd.TYPE_VALUE_GAUGE);
              for(double value : values) {
                System.out.println(value);
              }
            }
          }
        }
      } catch(Exception e) {
        e.printStackTrace();
      }
    }
  }

  public static final class Forwarder extends Thread {
    @Override
    public void run() {
      try {
        Collectd collectd = new Collectd()
            .setHostname(HOSTNAME_ENDPOINT)
            .bind();

        Collectd collectd_forward = new Collectd()
            .setUsername(FORWARD_USERNAME)
            .setPassword(FORWARD_PASSWORD)
            .setEndpointPort(25826 + 1)
            .setEndpointHostname(FORWARD_HOSTNAME_ENDPOINT)
            .connect();

        while(true) {
          ArrayList<CollectdPart> part_list = new ArrayList<>();
          collectd.recv(part_list, ON_CRYPTO);

          for(CollectdPart part : part_list) {
            if(part instanceof CollectdPart.HostPart) {
              CollectdPart.HostPart host_part = (CollectdPart.HostPart) part;
              System.out.println(host_part.getString());
              host_part.setString(FORWARD_HOSTNAME_OVERWRITE);
            }

            if(part instanceof CollectdPart.ValuePart) {
              double[] values = ((CollectdPart.ValuePart) part).getDoubleValues(Collectd.TYPE_VALUE_GAUGE);
              for(double value : values) {
                System.out.println(value);
              }
            }
          }

          collectd_forward.send(part_list);
        }
      } catch(Exception e) {
        e.printStackTrace();
      }
    }
  }

  public static final class Sender extends Thread {
    @Override
    public void run() {

      try {
        Collectd collectd = new Collectd()
            .setHostname(HOSTNAME)
            .setUsername(USERNAME)
            .setPassword(PASSWORD)
            .setEndpointHostname(HOSTNAME_ENDPOINT)
            .connect();

        CollectdProxy.CollectdGaugeProxy collectd_gauge_proxy = collectd
            .getGaugeProxy()
            .setPlugin("heuristic-A")
            .setPluginInstance("B")
            .setType("gauge")
            .setTypePart("function");

        CollectdTimer timer = collectd_gauge_proxy.getTimerProxy();

        while(true) {
          timer.time(() -> {
            try {
              Thread.sleep(Math.abs(new Random().nextLong()) % 1000);
            } catch(Exception e) {

            }
          });
        }
      } catch(Exception e) {
        e.printStackTrace();
      }
    }
  }
}
```