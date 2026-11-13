package ai.hb.smartdns;

import java.util.Arrays;

/** Strict DNS-only TUN decoder. Everything outside the two virtual DNS addresses is ignored. */
public final class PacketCodec {
    private PacketCodec() {}
    public static final byte[] DNS4={(byte)10,(byte)111,0,1};
    public static final byte[] DNS6={(byte)0xfd,(byte)0x66,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    public static int u16(byte[] b,int p){return ((b[p]&255)<<8)|(b[p+1]&255);}
    public static void w16(byte[] b,int p,int v){b[p]=(byte)(v>>8);b[p+1]=(byte)v;}
    private static long sum(byte[] b,int off,int len,long initial){
        for(int i=0;i<len;i+=2){int v=(b[off+i]&255)<<8;if(i+1<len)v|=b[off+i+1]&255;initial+=v;}
        return initial;
    }
    private static int finish(long s){while((s>>>16)!=0)s=(s&0xffff)+(s>>>16);return (int)(~s)&0xffff;}
    private static boolean equalsAddr(byte[] p,int off,byte[] addr){
        for(int i=0;i<addr.length;i++)if(p[off+i]!=addr[i])return false;return true;
    }
    public static final class Request {
        public final byte[] src,dst,dns;
        public final int version,srcPort;
        Request(int version,byte[] src,byte[] dst,int srcPort,byte[] dns){
            this.version=version;this.src=src;this.dst=dst;this.srcPort=srcPort;this.dns=dns;
        }
    }
    public static Request parse(byte[] packet,int length) {
        if(packet==null||length<28||length>packet.length)return null;
        int version=(packet[0]>>>4)&15, start, end, src, dst;
        if(version==4){
            int header=(packet[0]&15)*4;
            if(header<20||length<header+8||u16(packet,2)>length||u16(packet,2)<header+8)return null;
            if((u16(packet,6)&0x3fff)!=0)return null; // never parse fragmented packets
            if((packet[9]&255)!=17||!equalsAddr(packet,16,DNS4))return null;
            start=header;end=u16(packet,2);src=12;dst=16;
        }else if(version==6){
            if(length<48||(packet[6]&255)!=17||!equalsAddr(packet,24,DNS6))return null;
            start=40;end=40+u16(packet,4);src=8;dst=24;
            if(end>length)return null;
        }else return null;
        if(end<start+8 || u16(packet,start+2)!=53)return null;
        int size=u16(packet,start+4);
        if(size<8||start+size>end||start+size>length)return null;
        int srcPort=u16(packet,start);
        if(srcPort==0)return null;
        byte[] dns=Arrays.copyOfRange(packet,start+8,start+size);
        if(DnsEngine.questionEnd(dns)<0)return null;
        int alen=version==4?4:16;
        return new Request(version,Arrays.copyOfRange(packet,src,src+alen),Arrays.copyOfRange(packet,dst,dst+alen),srcPort,dns);
    }
    public static byte[] response(Request r,byte[] dns) {
        if(r==null||dns==null||dns.length<12||dns.length>4000)return null;
        // Never emit packets larger than the advertised 1500-byte TUN MTU.
        if(dns.length>(r.version==4?1472:1452))dns=DnsEngine.servfail(r.dns);
        boolean v4=r.version==4;
        int h=v4?20:40, u=8, size=h+u+dns.length;
        byte[] b=new byte[size];
        if(v4){
            b[0]=0x45;b[1]=0;w16(b,2,size);w16(b,4,0);w16(b,6,0);b[8]=64;b[9]=17;
            System.arraycopy(r.dst,0,b,12,4);System.arraycopy(r.src,0,b,16,4);
            w16(b,10,finish(sum(b,0,h,0)));
        }else{
            b[0]=0x60;w16(b,4,u+dns.length);b[6]=17;b[7]=64;
            System.arraycopy(r.dst,0,b,8,16);System.arraycopy(r.src,0,b,24,16);
        }
        w16(b,h,53);w16(b,h+2,r.srcPort);w16(b,h+4,u+dns.length);
        System.arraycopy(dns,0,b,h+8,dns.length);
        long pseudo=0;
        pseudo=sum(b,v4?12:8,v4?8:32,pseudo);
        if(v4)pseudo+=17+(u+dns.length);
        else pseudo+=(u+dns.length)+17;
        int checksum=finish(sum(b,h,u+dns.length,pseudo));
        w16(b,h+6,checksum==0?0xffff:checksum);
        return b;
    }
}
