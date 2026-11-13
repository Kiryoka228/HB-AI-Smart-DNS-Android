package ai.hb.smartdns;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** Local split-tunnel DNS VPN; all ordinary non-DNS destinations remain on the default network. */
public final class DnsVpnService extends VpnService {
    public static final String START_VPN="ai.hb.smartdns.START_VPN";
    public static final String START_ROOT="ai.hb.smartdns.START_ROOT";
    public static final String STOP="ai.hb.smartdns.STOP";
    private static final int NOTIF=38451;
    public static volatile String mode="off";
    public static volatile String error="";
    public static volatile int provider=0;
    private static volatile DnsVpnService instance;
    private volatile boolean running;
    private ParcelFileDescriptor tun;
    private Thread vpnReader;
    private ThreadPoolExecutor lookups;
    private DnsProxy rootProxy;
    private RootController rootDriver;
    private final Object tunWrite=new Object();

    public static boolean active(){return !mode.equals("off");}
    public static void setProvider(int p){
        if(p<0||p>3)return;provider=p;
        DnsVpnService obj=instance;
        if(obj!=null&&obj.rootProxy!=null)obj.rootProxy.setProvider(p);
    }
    public static void signalUi(){MainActivity.pushAll();}
    public static void launch(Context c,String action){
        Intent i=new Intent(c,DnsVpnService.class).setAction(action);
        if(Build.VERSION.SDK_INT>=26&&!action.equals(STOP))c.startForegroundService(i);
        else c.startService(i);
    }
    @Override public void onCreate(){super.onCreate();instance=this;rootDriver=new RootController(this);}
    private Notification notification(String message){
        if(Build.VERSION.SDK_INT>=26){
            NotificationChannel channel=new NotificationChannel("hb_dns","HB AI Smart DNS",NotificationManager.IMPORTANCE_LOW);
            ((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(channel);
        }
        Intent open=new Intent(this,MainActivity.class).setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP|Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent tap=PendingIntent.getActivity(this,10,open,PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        Intent stop=new Intent(this,DnsVpnService.class).setAction(STOP);
        PendingIntent off=PendingIntent.getService(this,11,stop,PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        return new Notification.Builder(this, "hb_dns")
            .setContentTitle("HB AI · Smart DNS")
            .setContentText(message).setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentIntent(tap)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel,"Отключить",off)
            .setOngoing(true).build();
    }
    private void foreground(String text, boolean root){
        Notification n=notification(text);
        if(Build.VERSION.SDK_INT>=34)startForeground(NOTIF,n,ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else startForeground(NOTIF,n);
    }
    @Override public int onStartCommand(Intent intent,int flags,int startId){
        final String action=intent==null?"":intent.getAction();
        if(STOP.equals(action)) {new Thread(()->{shutdown(true);stopSelf();},"HB-stop").start();return START_NOT_STICKY;}
        if(START_ROOT.equals(action)){
            if(running)return START_NOT_STICKY;
            foreground("Подключение root DNS…",true);
            new Thread(()->{
                try{
                    rootProxy=new DnsProxy(provider);
                    rootProxy.start(); // never intercept packets until the local listener is ready
                    rootDriver.enable(rootProxy.supportsIPv6());
                    running=true;mode="root";error="";
                    notifyUpdate("Root DNS активен");
                }catch(Exception e){
                    error="Root DNS: "+e.getMessage();
                    shutdown(true);stopSelf();MainActivity.fallbackFromRoot();
                }
                signalUi();
            },"HB-root").start();
        }else if(START_VPN.equals(action)){
            if(running)return START_NOT_STICKY;
            try{
                // Only the virtual DNS addresses are routed into this TUN, not all user traffic.
                Builder builder=new Builder()
                    .setSession("HB AI Smart DNS")
                    .setMtu(1500)
                    .addAddress("10.111.0.2",32)
                    .addRoute("10.111.0.1",32)
                    .addDnsServer("10.111.0.1")
                    .addAddress("fd66::2",128)
                    .addRoute("fd66::1",128)
                    .addDnsServer("fd66::1");
                foreground("Запуск локального DNS-VPN…",false);
                tun=builder.establish();
                if(tun==null)throw new Exception("Android не разрешил VPN-интерфейс");
                running=true;mode="vpn";error="";
                lookups=new ThreadPoolExecutor(3,8,30,TimeUnit.SECONDS,
                    new ArrayBlockingQueue<>(128),new ThreadPoolExecutor.AbortPolicy());
                startVpnReader();
                notifyUpdate("DNS-VPN активен");signalUi();
            }catch(Exception e){error="VPN: "+e.getMessage();shutdown(false);stopSelf();signalUi();}
        }
        return START_NOT_STICKY;
    }
    private void startVpnReader(){
        final ParcelFileDescriptor fd=tun;
        vpnReader=new Thread(()->{
            try(FileInputStream in=new FileInputStream(fd.getFileDescriptor());
                FileOutputStream out=new FileOutputStream(fd.getFileDescriptor())){
                byte[] buf=new byte[8192];
                while(running){
                    int n=in.read(buf);
                    if(n<=0)break;
                    PacketCodec.Request request=PacketCodec.parse(buf,n);
                    if(request==null)continue;
                    final int set=provider;
                    try{lookups.execute(()->{
                        byte[] answer=DnsEngine.forward(request.dns,set,new DnsEngine.Protect(){
                            @Override public boolean protect(java.net.DatagramSocket s){return DnsVpnService.this.protect(s);}
                            @Override public boolean protect(java.net.Socket s){return DnsVpnService.this.protect(s);}
                        });
                        byte[] reply=PacketCodec.response(request,answer);
                        if(reply!=null && running){
                            synchronized(tunWrite){try{out.write(reply);out.flush();}catch(Exception ignored){}}
                        }
                    });}catch(java.util.concurrent.RejectedExecutionException ignored){}
                }
            }catch(Exception e){if(running)error="TUN: "+e.getMessage();}
            if(running){shutdown(false);stopSelf();signalUi();}
        },"HB-TUN-reader");vpnReader.setDaemon(true);vpnReader.start();
    }
    private void notifyUpdate(String text){
        ((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(NOTIF,notification(text));
    }
    private synchronized void shutdown(boolean restoreRoot){
        running=false;
        if(tun!=null)try{tun.close();}catch(Exception ignored){}tun=null;
        if(lookups!=null)lookups.shutdownNow();lookups=null;
        if(restoreRoot){
            try{if(rootDriver.isActive())rootDriver.disable();}catch(Exception e){error="Откат root: "+e.getMessage();}
        }
        if(rootProxy!=null)rootProxy.close();rootProxy=null;
        mode="off";
        stopForeground(STOP_FOREGROUND_REMOVE);
        signalUi();
    }
    @Override public void onRevoke(){shutdown(true);stopSelf();super.onRevoke();}
    @Override public void onDestroy(){shutdown(true);instance=null;super.onDestroy();}
}
