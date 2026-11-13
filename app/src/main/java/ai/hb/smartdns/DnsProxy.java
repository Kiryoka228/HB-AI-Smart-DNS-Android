package ai.hb.smartdns;

import java.io.*;
import java.net.*;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Local UDP+TCP DNS for the root iptables OUTPUT REDIRECT route. */
public final class DnsProxy implements AutoCloseable {
    public static final int PORT=53535;
    private volatile boolean running;
    private DatagramSocket udp;
    private DatagramSocket udp6;
    private ServerSocket tcp;
    private ServerSocket tcp6;
    private final ExecutorService workers=Executors.newFixedThreadPool(12);
    private volatile int provider;
    public DnsProxy(int provider){this.provider=provider;}
    public void setProvider(int p){if(p>=0&&p<4)provider=p;}
    public boolean supportsIPv6(){return udp6!=null&&tcp6!=null;}
    public synchronized void start() throws IOException {
        if(running)return;
        udp=new DatagramSocket(null);
        udp.setReuseAddress(false);
        udp.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),PORT));
        try{
            tcp=new ServerSocket();tcp.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),PORT));
        }catch(IOException ex){udp.close();throw ex;}
        running=true;
        try {
            udp6=new DatagramSocket(new InetSocketAddress(InetAddress.getByName("::1"),PORT));
            tcp6=new ServerSocket();tcp6.bind(new InetSocketAddress(InetAddress.getByName("::1"),PORT));
        } catch(Exception ignored) { if(udp6!=null){udp6.close();udp6=null;} if(tcp6!=null)try{tcp6.close();}catch(Exception ignore){} tcp6=null; }
        serveUdp(udp);
        if(udp6!=null)serveUdp(udp6);
        serveTcp(tcp);
        if(tcp6!=null)serveTcp(tcp6);
    }
    private void serveUdp(DatagramSocket source){
        Thread t1=new Thread(()->{
            while(running){
                try {
                    byte[] b=new byte[4096];DatagramPacket req=new DatagramPacket(b,b.length);source.receive(req);
                    final byte[] query=Arrays.copyOfRange(req.getData(),req.getOffset(),req.getOffset()+req.getLength());
                    final SocketAddress client=req.getSocketAddress();
                    workers.execute(()->{
                        byte[] response=DnsEngine.forward(query,provider,null);
                        if(response.length<12)return;
                        try { synchronized(source){source.send(new DatagramPacket(response,response.length,client));} }
                        catch(IOException ignored){}
                    });
                }catch(Exception ignored){if(!running)break;}
            }
        },"HB-DNS-UDP");t1.setDaemon(true);t1.start();
    }
    private void serveTcp(ServerSocket source){
        Thread t2=new Thread(()->{
            while(running){
                try{
                    Socket s=source.accept();workers.execute(()->handleTcp(s));
                }catch(Exception ignored){if(!running)break;}
            }
        },"HB-DNS-TCP");t2.setDaemon(true);t2.start();
    }
    private void handleTcp(Socket socket){
        try(Socket s=socket){
            s.setSoTimeout(9000);
            DataInputStream in=new DataInputStream(s.getInputStream());
            DataOutputStream out=new DataOutputStream(s.getOutputStream());
            while(running){
                int n; try{n=in.readUnsignedShort();}catch(EOFException eof){break;}
                if(n<17||n>4096)break;
                byte[] q=new byte[n];in.readFully(q);
                byte[] answer=DnsEngine.forward(q,provider,null);
                if(answer.length<12)break;
                out.writeShort(answer.length);out.write(answer);out.flush();
            }
        }catch(IOException ignored){}
    }
    @Override public synchronized void close(){running=false;if(udp!=null)udp.close();if(udp6!=null)udp6.close();if(tcp!=null)try{tcp.close();}catch(IOException ignored){}if(tcp6!=null)try{tcp6.close();}catch(IOException ignored){}workers.shutdownNow();}
}
