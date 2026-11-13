package ai.hb.smartdns;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

/** DNS wire format and the exact provider list from desktop 1.23. No third-party dependencies. */
public final class DnsEngine {
    private DnsEngine() {}
    public static final String[][] DNS = {
        {"94.250.253.55", "212.109.195.93"},
        {"143.20.64.192", "5.175.161.40"},
        {"109.120.177.170", "45.88.163.92"},
        {"111.88.96.54", "111.88.96.55"}
    };
    public static final String[] NAMES = {"Comss.one", "GeoHide EU", "MagicDNS", "Xbox DNS"};
    public static final String[] SHORT = {"Comss", "GeoHide", "MagicDNS", "Xbox"};
    public static final String[] SITES = {"comss.ru", "geohide.ru", "magicdns.ru", "xbox-dns.ru"};
    public static final String[] URLS = {"https://www.comss.ru/", "https://geohide.ru/", "https://magicdns.ru/", "https://xbox-dns.ru/"};
    public static final String[] OPENS = {
        "ChatGPT, Claude, Gemini, ElevenLabs, Grok, Perplexity",
        "ChatGPT, Claude, Grok, Perplexity; ElevenLabs — через раз, Gemini — капча",
        "ChatGPT, ElevenLabs, Grok, Perplexity; Claude и Gemini — пока нет",
        "Только Xbox Live, нейросети — нет"
    };
    public static final String[][] HOSTS = {
        {"chatgpt.com", "ChatGPT"}, {"claude.ai", "Claude"},
        {"gemini.google.com", "Gemini"}, {"elevenlabs.io", "ElevenLabs"},
        {"grok.com", "Grok"}, {"www.perplexity.ai", "Perplexity"}
    };
    public static int u16(byte[] b, int off) { return ((b[off] & 255) << 8) | (b[off+1] & 255); }
    public static void put16(byte[] b, int off, int value) { b[off]=(byte)(value>>>8); b[off+1]=(byte)value; }
    public static void put32(byte[] b, int off, long value) { for(int i=3;i>=0;i--){ b[off+i]=(byte)value; value>>>=8; } }

    /** Return the end of one DNS question. Malformed questions never reach the upstream server. */
    public static int questionEnd(byte[] query) {
        if (query == null || query.length < 17 || u16(query,4) != 1) return -1;
        int p=12, labels=0;
        while (p < query.length && labels++ < 128) {
            int n=query[p++] & 255;
            if (n == 0) return p+4 <= query.length ? p+4 : -1;
            if (n > 63 || p+n > query.length) return -1;
            p+=n;
        }
        return -1;
    }
    public static byte[] queryA(String domain) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int id=new SecureRandom().nextInt(65536);
        out.write(id>>>8); out.write(id); out.write(1); out.write(0);  // RD
        out.write(0); out.write(1); for(int j=0;j<6;j++)out.write(0);
        for (String part:domain.split("\\.")) {
            byte[] l=part.getBytes(StandardCharsets.US_ASCII);
            if(l.length<1||l.length>63)throw new IllegalArgumentException("Bad DNS label");
            out.write(l.length);out.write(l,0,l.length);
        }
        out.write(0);out.write(0);out.write(1);out.write(0);out.write(1);
        return out.toByteArray();
    }
    /** Prevent IPv6 bypass for providers with only IPv4 DNS, returning valid empty AAAA answer. */
    public static byte[] blockedAAAA(byte[] q) {
        int end=questionEnd(q);
        if (end<0 || u16(q,end-4)!=28) return null;
        byte[] r=Arrays.copyOf(q,end);
        r[2]=(byte)0x81; r[3]=(byte)0x80;
        put16(r,6,0);put16(r,8,0);put16(r,10,0);
        return r;
    }
    public static byte[] servfail(byte[] q) {
        int end=questionEnd(q);
        if (end<0)return new byte[0];
        byte[] r=Arrays.copyOf(q,end);
        r[2]=(byte)0x81;r[3]=(byte)0x82;
        put16(r,6,0);put16(r,8,0);put16(r,10,0);
        return r;
    }
    public static String firstA(byte[] answer) {
        if (answer==null || answer.length<12 || (answer[3]&15)!=0) return null;
        int p=12, count=u16(answer,4);
        for (int i=0;i<count;i++) {
            int guard=0;
            while(p<answer.length && guard++<128) {
                int n=answer[p++] & 255;
                if(n==0)break;
                if((n&0xC0)==0xC0){if(p>=answer.length)return null;p++;break;}
                if(n>63||p+n>answer.length)return null;
                p+=n;
            }
            if(p+4>answer.length)return null;
            p+=4;
        }
        int records=u16(answer,6);
        for(int i=0;i<records;i++){
            int guard=0;
            while(p<answer.length && guard++<128){
                int n=answer[p++] & 255;
                if(n==0)break;
                if((n&0xC0)==0xC0){if(p>=answer.length)return null;p++;break;}
                if(n>63||p+n>answer.length)return null;
                p+=n;
            }
            if(p+10>answer.length)return null;
            int type=u16(answer,p), klass=u16(answer,p+2), size=u16(answer,p+8);
            p+=10;
            if(p+size>answer.length)return null;
            if(type==1&&klass==1&&size==4)
                return (answer[p]&255)+"."+(answer[p+1]&255)+"."+(answer[p+2]&255)+"."+(answer[p+3]&255);
            p+=size;
        }
        return null;
    }
    /** VPN protect is mandatory; without it resolver sockets could recursively enter the TUN. */
    public interface Protect { boolean protect(DatagramSocket socket); boolean protect(Socket socket); }
    public static byte[] forward(byte[] query, int provider, Protect protect) {
        if(provider<0||provider>3||questionEnd(query)<0)return servfail(query);
        if(provider!=3){byte[] blocked=blockedAAAA(query);if(blocked!=null)return blocked;}
        for(int attempt=0;attempt<4;attempt++) {
            try(DatagramSocket socket=new DatagramSocket()){
                if(protect!=null&&!protect.protect(socket))return servfail(query);
                socket.setSoTimeout(1900);
                String upstream=DNS[provider][attempt%2];
                InetAddress remote=InetAddress.getByName(upstream);
                DatagramPacket request=new DatagramPacket(query,query.length,remote,53);
                socket.send(request);
                byte[] buf=new byte[4096];
                DatagramPacket reply=new DatagramPacket(buf,buf.length);
                socket.receive(reply);
                if(reply.getAddress().equals(remote)&&reply.getLength()>=12 && buf[0]==query[0] && buf[1]==query[1]){
                    return Arrays.copyOf(buf,reply.getLength());
                }
            } catch(Exception ignored) { }
        }
        return servfail(query);
    }
    /** For diagnostics only: the desktop version intentionally doesn't verify the TLS certificate. */
    public static String checkSite(String host, String ip) {
        if(ip==null)return "DNS молчит";
        if(ip.equals("0.0.0.0"))return "не пускает";
        try {
            TrustManager[] trusts={new X509TrustManager(){
                public X509Certificate[] getAcceptedIssuers(){return new X509Certificate[0];}
                public void checkClientTrusted(X509Certificate[] c,String a){}
                public void checkServerTrusted(X509Certificate[] c,String a){}
            }};
            SSLContext context=SSLContext.getInstance("TLS");
            context.init(null,trusts,new SecureRandom());
            Socket transport=new Socket();
            transport.connect(new InetSocketAddress(ip,443),6000);
            transport.setSoTimeout(8000);
            try(SSLSocket ssl=(SSLSocket)context.getSocketFactory().createSocket(transport,host,443,true)){
                SSLParameters params=ssl.getSSLParameters();
                params.setServerNames(java.util.Collections.singletonList(new SNIHostName(host)));
                ssl.setSSLParameters(params);
                ssl.startHandshake();
                String req="GET / HTTP/1.1\r\nHost: "+host+"\r\nUser-Agent: Mozilla/5.0 (Android; HB-AI-SmartDNS)\r\nConnection: close\r\n\r\n";
                ssl.getOutputStream().write(req.getBytes(StandardCharsets.US_ASCII));
                InputStream in=ssl.getInputStream();byte[] b=new byte[4096];int n=in.read(b);
                if(n<=0)return "нет связи";
                String header=new String(b,0,n,StandardCharsets.UTF_8).toLowerCase(java.util.Locale.ROOT);
                if(header.contains("/sorry/"))return "капча Google";
                if(header.contains("restrict")||header.contains("unsupported")||header.contains("unavailable")||header.startsWith("http/1.1 451")||header.startsWith("http/1.0 451"))return "блок страны";
                return "открывается";
            }
        }catch(Exception ignored){return "нет связи";}
    }
    public static SiteResult probe(int provider, String[] site){
        byte[] ans=forward(queryA(site[0]),provider,null);
        String ip=firstA(ans);
        return new SiteResult(site[1],ip,checkSite(site[0],ip));
    }
    public static final class SiteResult {
        public final String label,ip,result;
        public SiteResult(String label,String ip,String result){this.label=label;this.ip=ip;this.result=result;}
    }
}
