package ai.hb.smartdns;

import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/** Per-device DNS path recovery. Never rewrites HTTPS traffic, suppresses TLS verification,
 * or assumes a GitHub runner's working IP is reachable from the user's Android network. */
public final class SmartRoute {
    private SmartRoute() {}
    public static final int MAX_IPS=6;
    private static final long CACHE_MS=45_000;
    private static final long NEGATIVE_CACHE_MS=25_000;
    private static final ExecutorService CHECKS=Executors.newFixedThreadPool(6);
    private static final Map<String,Selection> POSITIVE=new ConcurrentHashMap<>();
    private static final Map<String,Long> NEGATIVE=new ConcurrentHashMap<>();
    private static final AtomicLong checked=new AtomicLong(), selected=new AtomicLong(), fallback=new AtomicLong();
    private static volatile String last="Проверки маршрутов ещё не проводились";

    public static final class Selection {
        public final String ip,host;
        public final int provider;
        public final long until;
        Selection(String host,String ip,int provider,long until){this.host=host;this.ip=ip;this.provider=provider;this.until=until;}
    }
    public static long[] counters(){return new long[]{checked.get(),selected.get(),fallback.get()};}
    public static String lastDecision(){return last;}
    public static void invalidate(){POSITIVE.clear();NEGATIVE.clear();last="Повторная проверка при следующем DNS-запросе";}
    public static boolean protectedHost(String hostname) {
        if(hostname==null)return false;
        String h=hostname.toLowerCase(Locale.ROOT);
        return h.equals("chatgpt.com") || h.endsWith(".chatgpt.com")
            || h.equals("chat.openai.com") || h.equals("android.chat.openai.com")
            || h.equals("auth.openai.com") || h.endsWith(".auth.openai.com")
            || h.equals("auth0.openai.com") || h.equals("gemini.google.com");
    }
    public static boolean validPublicV4(String ip){
        try{
            String[] parts=ip.split("\\.");if(parts.length!=4)return false;
            int[] a=new int[4];
            for(int i=0;i<4;i++){a[i]=Integer.parseInt(parts[i]);if(a[i]<0||a[i]>255)return false;}
            if(a[0]==0||a[0]==10||a[0]==127||a[0]>=224||a[0]==169&&a[1]==254||a[0]==172&&a[1]>=16&&a[1]<=31||a[0]==192&&a[1]==168||a[0]==100&&a[1]>=64&&a[1]<=127)return false;
            return true;
        }catch(Exception e){return false;}
    }
    /** Only query type A; all other types, Android's regular DNS traffic and Xbox are unchanged. */
    public static byte[] forward(byte[] query,int provider,DnsEngine.Protect protection){
        String host=DnsEngine.questionName(query);
        if(provider<0||provider>=3||!protectedHost(host)||DnsEngine.questionType(query)!=1)
            return DnsEngine.forward(query,provider,protection);
        String cacheKey=provider+"|"+host;
        Selection cached=POSITIVE.get(cacheKey);
        if(cached!=null&&cached.until>System.currentTimeMillis()){
            selected.incrementAndGet();
            if(cached.provider!=provider)fallback.incrementAndGet();
            return DnsEngine.oneA(query,cached.ip,Math.max(1,(int)((cached.until-System.currentTimeMillis())/1000)));
        }
        // Don't bypass the user's DNS choice except for these known AI endpoints. Limit fallbacks
        // to the two Smart-DNS providers that actually returned valid HTTPS in independent tests.
        int[] order= provider==0?new int[]{0,1}:provider==1?new int[]{1,0}:new int[]{2,0,1};
        byte[] original=null;
        for(int p:order){
            // The initial selected DNS response is preserved if no verified path exists.
            byte[] raw=DnsEngine.forwardFast(query,p,protection);
            if(p==provider)original=raw;
            List<String> ips=DnsEngine.allA(raw);
            if(ips.isEmpty())continue;
            LinkedHashSet<String> candidates=new LinkedHashSet<>(ips);
            List<Future<String>> tasks=new ArrayList<>();
            for(String ip:candidates){
                if(tasks.size()>=MAX_IPS)break;
                if(!validPublicV4(ip))continue;
                String nk=host+"|"+ip;
                Long since=NEGATIVE.get(nk);
                if(since!=null&&since>System.currentTimeMillis())continue;
                tasks.add(CHECKS.submit(()->probeEndpoint(host,ip,protection)?ip:null));
            }
            for(Future<String> task:tasks){
                try{
                    String live=task.get(3300,TimeUnit.MILLISECONDS);
                    if(live!=null){
                        long until=System.currentTimeMillis()+CACHE_MS;
                        POSITIVE.put(cacheKey,new Selection(host,live,p,until));
                        selected.incrementAndGet();
                        if(p!=provider)fallback.incrementAndGet();
                        last=host+": HTTPS подтверждён через "+DnsEngine.SHORT[p]+" ("+live+")";
                        // Preserve real hostname, verified SNI and TLS certificate; change DNS A only.
                        for(Future<String> other:tasks)if(other!=task)other.cancel(true);
                        return DnsEngine.oneA(query,live,45);
                    }
                }catch(Exception ignored){task.cancel(true);}
            }
        }
        last=host+": нет подтверждённых HTTPS-узлов; исходный DNS-ответ сохранён";
        return original==null?DnsEngine.servfail(query):original;
    }
    /** A GET / probe confirms HTTPS server reachability, not account login or Gemini API access. */
    private static boolean probeEndpoint(String host,String ip,DnsEngine.Protect protection){
        checked.incrementAndGet();
        Socket tcp=new Socket();
        try{
            if(protection!=null&&!protection.protect(tcp))return false;
            tcp.connect(new InetSocketAddress(ip,443),1200);
            tcp.setSoTimeout(1900);
            try(SSLSocket ssl=(SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(tcp,host,443,true)){
                SSLParameters params=ssl.getSSLParameters();
                params.setEndpointIdentificationAlgorithm("HTTPS");
                params.setServerNames(Collections.singletonList(new SNIHostName(host)));
                ssl.setSSLParameters(params);
                ssl.startHandshake();
                byte[] request=("GET / HTTP/1.1\r\nHost: "+host+"\r\nUser-Agent: HB-SmartDNS-Android/1.26\r\nAccept: text/html\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
                ssl.getOutputStream().write(request);
                byte[] reply=new byte[256];InputStream in=ssl.getInputStream();int n=in.read(reply);
                if(n<12)return false;
                String head=new String(reply,0,n,StandardCharsets.ISO_8859_1);
                int end=head.indexOf('\n');if(end<0)return false;
                String[] fields=head.substring(0,end).trim().split(" +");
                if(fields.length<2 || !fields[0].startsWith("HTTP/"))return false;
                int code=Integer.parseInt(fields[1]);
                boolean ok=(code>=200&&code<400);
                if(!ok)NEGATIVE.put(host+"|"+ip,System.currentTimeMillis()+NEGATIVE_CACHE_MS);
                return ok;
            }
        }catch(Exception e){
            NEGATIVE.put(host+"|"+ip,System.currentTimeMillis()+NEGATIVE_CACHE_MS);
            return false;
        }finally{try{tcp.close();}catch(Exception ignored){}}
    }
    // This is deliberately deterministic and does not perform any network operations (for offline tests).
    public static String firstLiveForTest(String host,List<String> ips,Map<String,Boolean> reachability){
        if(!protectedHost(host))return null;
        for(String ip:ips)if(validPublicV4(ip)&&Boolean.TRUE.equals(reachability.get(ip)))return ip;
        return null;
    }
}
