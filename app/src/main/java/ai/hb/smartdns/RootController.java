package ai.hb.smartdns;

import android.content.Context;
import android.content.SharedPreferences;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/** Owns dedicated netfilter chains; never flushes chains managed by other apps. */
public final class RootController {
    private static final String C4="HB_AI_DNS4", C6="HB_AI_DNS6";
    private final Context context;
    private final SharedPreferences prefs;
    private static final int TIMEOUT=15000;
    public RootController(Context c){context=c.getApplicationContext();prefs=context.getSharedPreferences("dns",0);}
    public static final class Outcome {
        public final int code;public final String output;
        Outcome(int code,String output){this.code=code;this.output=output;}
    }
    private static Outcome execute(String command,long timeout)throws Exception{
        Process p=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();
        if(!p.waitFor(timeout,TimeUnit.MILLISECONDS)){
            p.destroyForcibly();throw new Exception("Превышено время ожидания su — проверьте менеджер root");
        }
        ByteArrayOutputStream b=new ByteArrayOutputStream();
        try(InputStream in=p.getInputStream()){
            byte[] tmp=new byte[1024];int n;
            while((n=in.read(tmp))!=-1&&b.size()<65536)b.write(tmp,0,n);
        }
        return new Outcome(p.exitValue(),b.toString("UTF-8").trim());
    }
    private static String require(String command)throws Exception{
        Outcome r=execute(command,TIMEOUT);
        if(r.code!=0)throw new Exception("su: "+r.output+" (код "+r.code+")");
        return r.output;
    }
    public boolean available(){
        try{return "0".equals(require("id -u").trim());}catch(Exception ignored){return false;}
    }
    private static String quoted(String s){return "'"+s.replace("'","'\\''")+"'";}
    private static String cleanup(boolean restore,String mode){
        String script=""+
            "iptables -t nat -D OUTPUT -j "+C4+" 2>/dev/null || :\n"+
            "iptables -t nat -F "+C4+" 2>/dev/null || :\n"+
            "iptables -t nat -X "+C4+" 2>/dev/null || :\n"+
            "ip6tables -t nat -D OUTPUT -j "+C6+" 2>/dev/null || :\n"+
            "ip6tables -t nat -F "+C6+" 2>/dev/null || :\n"+
            "ip6tables -t nat -X "+C6+" 2>/dev/null || :\n";
        if(restore)script+=mode.equals("null")?"settings delete global private_dns_mode\n":"settings put global private_dns_mode "+mode+"\n";
        return script;
    }
    public synchronized void enable(boolean ipv6Ready)throws Exception{
        if(!available())throw new Exception("Менеджер root не разрешил доступ su");
        String original=require("settings get global private_dns_mode").trim();
        if(!original.equals("off")&&!original.equals("opportunistic")&&!original.equals("hostname")&&!original.equals("null"))original="opportunistic";
        final String old=original;
        int uid=android.os.Process.myUid();
        String script="set -eu\n"+cleanup(false,old)+
            "iptables -t nat -N "+C4+"\n"+
            "iptables -t nat -A "+C4+" -m owner --uid-owner "+uid+" -j RETURN\n"+
            "iptables -t nat -A "+C4+" -p udp --dport 53 -j REDIRECT --to-ports "+DnsProxy.PORT+"\n"+
            "iptables -t nat -A "+C4+" -p tcp --dport 53 -j REDIRECT --to-ports "+DnsProxy.PORT+"\n"+
            "iptables -t nat -I OUTPUT 1 -j "+C4+"\n"+
            // IPv6 redirect only if the actual local IPv6 DNS listener was successfully bound.
            (ipv6Ready?"if ip6tables -t nat -N "+C6+" 2>/dev/null; then\n"+
            " ip6tables -t nat -A "+C6+" -m owner --uid-owner "+uid+" -j RETURN\n"+
            " ip6tables -t nat -A "+C6+" -p udp --dport 53 -j REDIRECT --to-ports "+DnsProxy.PORT+"\n"+
            " ip6tables -t nat -A "+C6+" -p tcp --dport 53 -j REDIRECT --to-ports "+DnsProxy.PORT+"\n"+
            " ip6tables -t nat -I OUTPUT 1 -j "+C6+" || :\n"+
            "fi\n":"")+
            "settings put global private_dns_mode off\n";
        prefs.edit().putString("previousDnsMode",old).putBoolean("rootActive",true).commit();
        try{
            require(script);
            require("iptables -t nat -C OUTPUT -j "+C4);
            installWatchdog(old);
        }catch(Exception ex){
            try{require(cleanup(true,old));}catch(Exception ignored){}
            new File(context.getFilesDir(),"dns-watchdog.state").delete();
            prefs.edit().putBoolean("rootActive",false).apply();
            throw ex;
        }
    }
    /** The watchdog has its own root shell process, to undo rules if Android kills this process. */
    private void installWatchdog(String mode)throws Exception{
        long pid=android.os.Process.myPid();
        File file=new File(context.getFilesDir(),"dns-watchdog.sh");
        File stamp=new File(context.getFilesDir(),"dns-watchdog.state");
        String identity=pid+"-"+System.nanoTime();
        try(FileOutputStream state=new FileOutputStream(stamp)){state.write(identity.getBytes(StandardCharsets.US_ASCII));}
        String script="#!/system/bin/sh\nPID="+pid+"\n"+
            "STAMP="+quoted(stamp.getAbsolutePath())+"\n"+
            "EXPECTED="+quoted(identity)+"\n"+
            "while kill -0 \"$PID\" 2>/dev/null; do sleep 4; done\n"+
            "[ \"$(cat \"$STAMP\" 2>/dev/null)\" = \"$EXPECTED\" ] || exit 0\n"+
            cleanup(true,mode)+"rm -f \"$STAMP\"\n";
        try(FileOutputStream out=new FileOutputStream(file)){
            out.write(script.getBytes(StandardCharsets.UTF_8));
        }
        require("chmod 700 "+quoted(file.getAbsolutePath()));
        // Parent exits immediately; the child remains alive as a separate root shell.
        require("(sh "+quoted(file.getAbsolutePath())+" </dev/null >/dev/null 2>&1 &)");
    }
    public synchronized void disable()throws Exception{
        String mode=prefs.getString("previousDnsMode","opportunistic");
        if(!mode.equals("off")&&!mode.equals("opportunistic")&&!mode.equals("hostname")&&!mode.equals("null"))mode="opportunistic";
        require(cleanup(true,mode));
        Outcome check=execute("iptables -t nat -C OUTPUT -j "+C4,5000);
        if(check.code==0)throw new Exception("Правила iptables не удалось полностью удалить");
        new File(context.getFilesDir(),"dns-watchdog.state").delete();
        prefs.edit().putBoolean("rootActive",false).apply();
    }
    public synchronized void recoverStale()throws Exception{
        // Called only after restart when no controller service is active.
        if(!prefs.getBoolean("rootActive",false))return;
        String mode=prefs.getString("previousDnsMode","opportunistic");
        if(!mode.equals("off")&&!mode.equals("opportunistic")&&!mode.equals("hostname")&&!mode.equals("null"))mode="opportunistic";
        require(cleanup(true,mode));
        new File(context.getFilesDir(),"dns-watchdog.state").delete();
        prefs.edit().putBoolean("rootActive",false).apply();
    }
    public boolean isActive(){
        if(!prefs.getBoolean("rootActive",false))return false;
        try{return execute("iptables -t nat -C OUTPUT -j "+C4,5000).code==0;}catch(Exception ignored){return false;}
    }
}
