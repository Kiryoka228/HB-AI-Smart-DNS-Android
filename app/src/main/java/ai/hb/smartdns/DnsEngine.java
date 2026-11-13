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
    /** Parse a plain DNS question name; exclude compression/invalid labels from smart routing. */
    public static String questionName(byte[] query){
        if(questionEnd(query)<0)return null;
        int p=12;StringBuilder domain=new StringBuilder();
        while(p<query.length){
            int n=query[p++]&255;if(n==0)break;
            if(n<1||n>63||p+n>query.length)return null;
            if(domain.length()>0)domain.append('.');
            for(int i=0;i<n;i++){
                int c=query[p+i]&255;
                if(!(c>=48&&c<=57||c>=65&&c<=90||c>=97&&c<=122||c==45))return null;
                domain.append((char)c);
            }
            p+=n;
        }
        return domain.toString().toLowerCase(java.util.Locale.ROOT);
    }
    public static int questionType(byte[] query){
        int end=questionEnd(query);
        if(end<0||u16(query,end-2)!=1)return -1;
        return u16(query,end-4);
    }
    /** Enumerate IPv4 RDATA from answer records, skipping name aliases and unrelated RR types. */
    public static List<String> allA(byte[] answer){
        List<String> found=new ArrayList<>();
        if(answer==null||answer.length<12||(answer[3]&15)!=0)return found;
        int q=u16(answer,4), p=12;
        if(q<1||q>8)return found;
        for(int i=0;i<q;i++){
            p=skipDnsName(answer,p);
            if(p<0||p+4>answer.length)return found;
            p+=4;
        }
        int count=Math.min(u16(answer,6),64);
        for(int i=0;i<count;i++){
            p=skipDnsName(answer,p);
            if(p<0||p+10>answer.length)break;
            int type=u16(answer,p), cls=u16(answer,p+2), size=u16(answer,p+8);
            p+=10;if(p+size>answer.length)break;
            if(type==1&&cls==1&&size==4){
                String ip=(answer[p]&255)+"."+(answer[p+1]&255)+"."+(answer[p+2]&255)+"."+(answer[p+3]&255);
                if(!found.contains(ip))found.add(ip);
            }
            p+=size;
        }
        return found;
    }
    private static int skipDnsName(byte[] data,int offset){
        for(int guard=0;guard<128;guard++){
            if(offset>=data.length)return -1;
            int len=data[offset++]&255;
            if(len==0)return offset;
            if((len&0xc0)==0xc0)return offset<data.length?offset+1:-1;
            if(len>63||offset+len>data.length)return -1;
            offset+=len;
        }
        return -1;
    }
    /** Return one IP that was verified for this hostname, with a short TTL and original DNS ID. */
    public static byte[] oneA(byte[] query,String ip,int ttl){
        int end=questionEnd(query);
        if(end<0||questionType(query)!=1)return servfail(query);
        try{
            String[] parts=ip.split("\\.");if(parts.length!=4)throw new Exception();
            byte[] response=Arrays.copyOf(query,end+16);
            response[2]=(byte)0x81;response[3]=(byte)0x80;
            put16(response,4,1);put16(response,6,1);put16(response,8,0);put16(response,10,0);
            int p=end;response[p++]=(byte)0xc0;response[p++]=12;
            put16(response,p,1);p+=2;put16(response,p,1);p+=2;
            put32(response,p,Math.max(1,Math.min(ttl,60)));p+=4;
            put16(response,p,4);p+=2;
            for(String part:parts){int v=Integer.parseInt(part);if(v<0||v>255)throw new Exception();response[p++]=(byte)v;}
            return response;
        }catch(Exception e){return servfail(query);}
    }
    /** VPN protect is mandatory; without it resolver sockets could recursively enter the TUN. */
    public interface Protect { boolean protect(DatagramSocket socket); boolean protect(Socket socket); }
    public static byte[] forward(byte[] query, int provider, Protect protect) {
        return forwardWithTimeout(query,provider,protect,4,1900);
    }
    /** AI failover uses shorter bounded retries; ordinary DNS preserves the original policy. */
    public static byte[] forwardFast(byte[] query, int provider, Protect protect) {
        return forwardWithTimeout(query,provider,protect,2,1100);
    }
    private static byte[] forwardWithTimeout(byte[] query,int provider,Protect protect,int attempts,int timeout) {
        if(provider<0||provider>3||questionEnd(query)<0)return servfail(query);
        if(provider!=3){byte[] blocked=blockedAAAA(query);if(blocked!=null)return blocked;}
        for(int attempt=0;attempt<attempts;attempt++) {
            try(DatagramSocket socket=new DatagramSocket()){
                if(protect!=null&&!protect.protect(socket))return servfail(query);
                socket.setSoTimeout(timeout);
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
    /** A network-level check, never proof that a logged-in Android app is supported. */
    public static String checkSite(String host, String ip) {
        if(ip==null)return "DNS молчит";
        if(ip.equals("0.0.0.0"))return "DNS блокирует";
        try {
            Socket transport=new Socket();
            transport.connect(new InetSocketAddress(ip,443),5500);
            transport.setSoTimeout(7000);
            try(SSLSocket ssl=(SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(transport,host,443,true)) {
                SSLParameters params=ssl.getSSLParameters();
                params.setServerNames(java.util.Collections.singletonList(new SNIHostName(host)));
                params.setEndpointIdentificationAlgorithm("HTTPS");
                ssl.setSSLParameters(params);
                ssl.startHandshake();
                String req="GET / HTTP/1.1\r\nHost: "+host+"\r\nUser-Agent: Mozilla/5.0 (Android; HB-AI-SmartDNS)\r\nAccept: text/html\r\nConnection: close\r\n\r\n";
                ssl.getOutputStream().write(req.getBytes(StandardCharsets.US_ASCII));
                InputStream in=ssl.getInputStream();byte[] buf=new byte[8192];int n=in.read(buf);
                if(n<=0)return "TLS есть, HTTP молчит";
                String content=new String(buf,0,n,StandardCharsets.UTF_8).toLowerCase(java.util.Locale.ROOT);
                int lineEnd=content.indexOf('\n');
                String first=(lineEnd<0?content:content.substring(0,lineEnd)).trim();
                if(!first.startsWith("http/"))return "Необычный HTTP-ответ";
                String[] bits=first.split(" +");
                if(bits.length<2)return "Неясный HTTP-ответ";
                int code=Integer.parseInt(bits[1]);
                if(code==403||code==401||code==451)return "HTTP "+code+" · доступ ограничен";
                if(content.contains("captcha")||content.contains("/sorry/")||content.contains("cf-chl-"))return "Проверка / CAPTCHA";
                if(code>=200&&code<300)return "HTTP "+code+" · сервер отвечает";
                if(code>=300&&code<400)return "HTTP "+code+" · перенаправление";
                if(code>=400)return "HTTP "+code+" · ошибка/ограничение";
                return "HTTP "+code;
            }
        } catch(javax.net.ssl.SSLHandshakeException e) {
            return "TLS: сертификат или соединение";
        } catch(Exception ignored) {return "Нет HTTPS-связи";}
    }
    public static boolean httpSuccess(String result){return result!=null&&result.matches("HTTP 2[0-9][0-9] \u00b7 сервер отвечает");}
    public static SiteResult probe(int provider, String[] site){
        byte[] ans=(provider<3 && SmartRoute.protectedHost(site[0]))
            ?SmartRoute.forward(queryA(site[0]),provider,null)
            :forward(queryA(site[0]),provider,null);
        String ip=firstA(ans);
        return new SiteResult(site[1],ip,checkSite(site[0],ip));
    }
    public static final class SiteResult {
        public final String label,ip,result;
        public SiteResult(String label,String ip,String result){this.label=label;this.ip=ip;this.result=result;}
    }
}
