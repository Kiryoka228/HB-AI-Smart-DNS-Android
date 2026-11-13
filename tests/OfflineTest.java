import ai.hb.smartdns.*;
import java.net.*;
import java.util.*;
import java.io.*;

public final class OfflineTest {
    static int passed=0;
    static void test(String label,boolean cond){if(!cond)throw new AssertionError(label);System.out.println("OK: "+label);passed++;}
    static byte[] dnsAAAA(){byte[] q=DnsEngine.queryA("chatgpt.com");int p=q.length; q[p-4]=0;q[p-3]=28;return q;}
    static byte[] ip4(byte[] dns){
        byte[] b=new byte[28+dns.length];b[0]=0x45;PacketCodec.w16(b,2,b.length);b[8]=64;b[9]=17;
        System.arraycopy(new byte[]{10,111,0,2},0,b,12,4);
        System.arraycopy(new byte[]{10,111,0,1},0,b,16,4);
        PacketCodec.w16(b,20,55343);PacketCodec.w16(b,22,53);
        PacketCodec.w16(b,24,dns.length+8);
        System.arraycopy(dns,0,b,28,dns.length);return b;
    }
    static byte[] ip6(byte[] dns){
        byte[] b=new byte[48+dns.length];b[0]=0x60;PacketCodec.w16(b,4,8+dns.length);b[6]=17;b[7]=64;
        b[8]=(byte)0xfd;b[9]=0x66;b[23]=2;
        b[24]=(byte)0xfd;b[25]=0x66;b[39]=1;
        PacketCodec.w16(b,40,55343);PacketCodec.w16(b,42,53);PacketCodec.w16(b,44,8+dns.length);
        System.arraycopy(dns,0,b,48,dns.length);return b;
    }
    public static void main(String[] args)throws Exception{
        test("4 original DNS sets",DnsEngine.DNS.length==4);
        test("6 site probes",DnsEngine.HOSTS.length==6);
        byte[] a=DnsEngine.queryA("chatgpt.com");
        test("A DNS question valid",DnsEngine.questionEnd(a)==a.length);
        test("A not blocked",DnsEngine.blockedAAAA(a)==null);
        byte[] q=dnsAAAA();
        byte[] reject=DnsEngine.blockedAAAA(q);
        test("AAAA returns NOERROR empty",reject.length==q.length&&DnsEngine.u16(reject,6)==0&&(reject[3]&15)==0);
        test("SERVFAIL for bad upstream",(DnsEngine.servfail(q)[3]&15)==2);
        byte[] answer=Arrays.copyOf(a,a.length+16);
        answer[2]=(byte)0x81;answer[3]=(byte)0x80;DnsEngine.put16(answer,6,1);
        int p=a.length;answer[p++]=(byte)0xc0;answer[p++]=12;answer[p++]=0;answer[p++]=1;answer[p++]=0;answer[p++]=1;
        answer[p++]=0;answer[p++]=0;answer[p++]=0;answer[p++]=90;answer[p++]=0;answer[p++]=4;
        answer[p++]=1;answer[p++]=2;answer[p++]=3;answer[p++]=4;
        test("DNS A answer parse", "1.2.3.4".equals(DnsEngine.firstA(answer)));
        byte[] multiple=Arrays.copyOf(a,a.length+32);
        multiple[2]=(byte)0x81;multiple[3]=(byte)0x80;DnsEngine.put16(multiple,6,2);
        for(int k=0;k<2;k++){
            int o=a.length+k*16;multiple[o]=(byte)0xc0;multiple[o+1]=12;
            DnsEngine.put16(multiple,o+2,1);DnsEngine.put16(multiple,o+4,1);
            DnsEngine.put32(multiple,o+6,90);DnsEngine.put16(multiple,o+10,4);
            multiple[o+12]=5;multiple[o+13]=6;multiple[o+14]=7;multiple[o+15]=(byte)(8+k);
        }
        test("DNS enumerates multiple A addresses",DnsEngine.allA(multiple).equals(Arrays.asList("5.6.7.8","5.6.7.9")));
        test("Only Gemini and ChatGPT families use guarded routing",SmartRoute.protectedHost("gemini.google.com")&&SmartRoute.protectedHost("CHATGPT.COM")&&!SmartRoute.protectedHost("example.com")&&!SmartRoute.protectedHost("evilchatgpt.com"));
        test("DNS question name decoded safely","chatgpt.com".equals(DnsEngine.questionName(a))&&DnsEngine.questionType(a)==1);
        byte[] repaired=DnsEngine.oneA(a,"5.175.161.40",45);
        test("Verified one-A response keeps original ID and TTL",repaired.length==a.length+16&&repaired[0]==a[0]&&repaired[1]==a[1]&&DnsEngine.u16(repaired,6)==1&&DnsEngine.u16(repaired,a.length+6)==0&&DnsEngine.allA(repaired).equals(Collections.singletonList("5.175.161.40")));
        test("No localhost/private DNS-target substitution",!SmartRoute.validPublicV4("127.0.0.1")&&!SmartRoute.validPublicV4("10.2.3.4")&&!SmartRoute.validPublicV4("0.0.0.0")&&SmartRoute.validPublicV4("5.175.161.40"));
        java.util.Map<String,Boolean> sim=new java.util.HashMap<>();sim.put("5.6.7.8",false);sim.put("5.6.7.9",true);
        test("Bad IP is rejected and healthy IP selected", "5.6.7.9".equals(SmartRoute.firstLiveForTest("chatgpt.com",DnsEngine.allA(multiple),sim)));
        test("Do not rewrite unrelated domain",SmartRoute.firstLiveForTest("example.com",DnsEngine.allA(multiple),sim)==null);
        test("Do not return an unverified candidate",SmartRoute.firstLiveForTest("gemini.google.com",Collections.singletonList("5.6.7.8"),sim)==null);
        byte[] v4=ip4(q);PacketCodec.Request r4=PacketCodec.parse(v4,v4.length);
        test("IPv4 TUN receives DNS",r4!=null&&r4.version==4&&r4.srcPort==55343);
        byte[] v4reply=PacketCodec.response(r4,reject);
        test("IPv4 response target",v4reply.length==28+reject.length&&v4reply[12]==10&&v4reply[15]==1&&PacketCodec.u16(v4reply,20)==53);
        byte[] v6=ip6(q);PacketCodec.Request r6=PacketCodec.parse(v6,v6.length);
        test("IPv6 TUN receives DNS",r6!=null&&r6.version==6);
        byte[] v6reply=PacketCodec.response(r6,reject);
        test("IPv6 response target",v6reply.length==48+reject.length&&v6reply[8]==(byte)0xfd&&v6reply[23]==1);
        byte[] invalid=Arrays.copyOf(v4,v4.length);invalid[16]=1;
        test("TUN ignores unrelated destinations",PacketCodec.parse(invalid,invalid.length)==null);
        invalid=Arrays.copyOf(v4,v4.length);invalid[6]=0x20;
        test("TUN rejects IP fragments",PacketCodec.parse(invalid,invalid.length)==null);
        test("Diagnose unavailable DNS",DnsEngine.checkSite("example.org",null).equals("DNS молчит"));
        test("HTTP 200 counts only as a reachable server",DnsEngine.httpSuccess("HTTP 200 · сервер отвечает"));
        test("HTTP 403 isn't accessible",!DnsEngine.httpSuccess("HTTP 403 · доступ ограничен"));
        test("HTTP 302 isn't a logged-in site",!DnsEngine.httpSuccess("HTTP 302 · перенаправление"));
        test("TLS without HTTP isn't success",!DnsEngine.httpSuccess("TLS есть, HTTP молчит"));
        DnsProxy proxy=new DnsProxy(0);
        try{
            proxy.start();
            try(DatagramSocket s=new DatagramSocket()){
                s.setSoTimeout(2000);
                s.send(new DatagramPacket(q,q.length,InetAddress.getLoopbackAddress(),DnsProxy.PORT));
                byte[] buf=new byte[1024];DatagramPacket resp=new DatagramPacket(buf,buf.length);s.receive(resp);
                test("Root UDP proxy AAAA filtering",resp.getLength()==q.length && DnsEngine.u16(buf,6)==0);
                test("Root proxy has real request and reply counters",proxy.stats()[0]>=1 && proxy.stats()[1]>=1);
            }
            try(Socket s=new Socket("127.0.0.1",DnsProxy.PORT)){
                s.setSoTimeout(2000);DataOutputStream out=new DataOutputStream(s.getOutputStream());DataInputStream in=new DataInputStream(s.getInputStream());
                out.writeShort(q.length);out.write(q);out.flush();
                int n=in.readUnsignedShort();byte[] resp=new byte[n];in.readFully(resp);
                test("Root TCP proxy AAAA filtering",n==q.length&&DnsEngine.u16(resp,6)==0);
                test("Root proxy counts TCP DNS as well",proxy.stats()[0]>=2 && proxy.stats()[1]>=2);
            }
        }finally{proxy.close();}
        System.out.println("PASS: "+passed+" offline tests");
    }
}
