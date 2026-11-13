package ai.hb.smartdns;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.provider.Settings;
import java.net.InetAddress;
import android.net.VpnService;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.view.WindowManager;
import org.json.JSONArray;
import org.json.JSONObject;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public final class MainActivity extends Activity {
    private static final int VPN_PERMISSION_REQUEST=2317;
    private static volatile WeakReference<MainActivity> current=new WeakReference<>(null);
    private final ExecutorService jobs=Executors.newCachedThreadPool();
    private final ExecutorService probes=Executors.newFixedThreadPool(8);
    private WebView web;
    private volatile boolean rootAvailable=false,rootChecked=false,probeBusy=false,systemBusy=false;
    private volatile int selected=0;

    @Override public void onCreate(Bundle saved){
        super.onCreate(saved);
        current=new WeakReference<>(this);
        selected=getPreferences(0).getInt("selected",0);
        if(selected<0||selected>3)selected=0;
        DnsVpnService.setProvider(selected);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS,WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
        getWindow().setStatusBarColor(0xff07070b);
        getWindow().setNavigationBarColor(0xff07070b);
        web=new WebView(this);
        setContentView(web);
        WebSettings s=web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(true); // required solely for bundled file:///android_asset content
        s.setAllowContentAccess(false);
        s.setAllowFileAccessFromFileURLs(false);
        s.setAllowUniversalAccessFromFileURLs(false);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        web.setWebChromeClient(new WebChromeClient());
        web.setWebViewClient(new WebViewClient(){
            @Override public boolean shouldOverrideUrlLoading(WebView v,WebResourceRequest req){return route(req.getUrl().toString());}
            @Override public boolean shouldOverrideUrlLoading(WebView v,String url){return route(url);}
            private boolean route(String url){
                if(url.equals("file:///android_asset/web/index.html"))return false;
                if(url.startsWith("https://")||url.startsWith("http://")){
                    try{startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse(url)));}catch(Exception ignored){}
                }
                return true; // no untrusted pages inside a privileged WebView
            }
        });
        web.addJavascriptInterface(new Bridge(),"HBAndroid");
        web.loadUrl("file:///android_asset/web/index.html");
        // Check immediately so Magisk/KernelSU can ask for su permission if installed.
        jobs.execute(()->{
            RootController driver=new RootController(this);
            rootAvailable=driver.available();
            if(rootAvailable&&!DnsVpnService.active())try{driver.recoverStale();}catch(Exception ignored){}
            rootChecked=true;
            pushAll();
        });
    }
    public static void pushAll(){
        MainActivity a=current.get();if(a!=null)a.pushStatus();
    }
    /** When su exists but the OEM blocks netfilter, request VPN permission instead. */
    public static void fallbackFromRoot(){
        MainActivity a=current.get();
        if(a!=null){a.rootAvailable=false;a.systemBusy=false;a.requestVpn();a.pushStatus();}
    }
    private void pushStatus(){
        if(DnsVpnService.active() || !DnsVpnService.error.isEmpty())systemBusy=false;
        try{
            final String json=status().toString();
            runOnUiThread(()->{if(web!=null)web.evaluateJavascript("window.HBTransport&&HBTransport.push("+JSONObject.quote(json)+")",null);});
        }catch(Exception ignored){}
    }
    private boolean modeActive(){return DnsVpnService.active();}
    private JSONObject status()throws Exception{
        JSONObject obj=new JSONObject();
        obj.put("token","apk-bridge");obj.put("selected",selected);
        obj.put("active",modeActive());obj.put("mode",DnsVpnService.mode);
        obj.put("error",DnsVpnService.error);
        obj.put("root",rootAvailable);obj.put("rootChecked",rootChecked);
        obj.put("systemBusy",systemBusy);obj.put("probeBusy",probeBusy);
        long[] stats=DnsVpnService.stats();
        obj.put("dnsRequests",stats[0]);obj.put("dnsReplies",stats[1]);obj.put("dnsFailures",stats[2]);
        String privateDns="неизвестно";
        try{
            String value=Settings.Global.getString(getContentResolver(),"private_dns_mode");
            if(value!=null)privateDns=value;
        }catch(Exception ignored){}
        obj.put("privateDnsMode",privateDns);
        obj.put("dnsObserved",stats[0]>0 && stats[1]>0);
        obj.put("dnsStatus",stats[0]==0?"Перехват не подтверждён: DNS-запросов пока не видно."
                :"Перехвачено: "+stats[0]+" · ответов: "+stats[1]+" · ошибок DNS: "+stats[2]);
        JSONArray services=new JSONArray();
        for(int i=0;i<4;i++){
            JSONObject p=new JSONObject();
            p.put("name",DnsEngine.NAMES[i]);p.put("short",DnsEngine.SHORT[i]);
            p.put("site",DnsEngine.SITES[i]);p.put("url",DnsEngine.URLS[i]);
            p.put("v4",new JSONArray(Arrays.asList(DnsEngine.DNS[i])));
            p.put("v6",new JSONArray(i==3?Arrays.asList("2a00:ab00:1233:26::50","2a00:ab00:1233:26::51"):new ArrayList<>()));
            p.put("opens",DnsEngine.OPENS[i]);services.put(p);
        }
        obj.put("services",services);return obj;
    }
    private JSONObject probeProvider(int p)throws Exception{
        List<Future<DnsEngine.SiteResult>> futures=new ArrayList<>();
        for(String[] site:DnsEngine.HOSTS){
            final String[] host=site;
            futures.add(probes.submit(()->DnsEngine.probe(p,host)));
        }
        JSONArray rows=new JSONArray();int good=0;
        for(Future<DnsEngine.SiteResult> future:futures){
            DnsEngine.SiteResult r=future.get();
            JSONObject row=new JSONObject();row.put("label",r.label);
            row.put("ip",r.ip==null?JSONObject.NULL:r.ip);
            row.put("result",r.result);rows.put(row);
            if(DnsEngine.httpSuccess(r.result))good++;
        }
        return new JSONObject().put("set",p).put("rows",rows).put("good",good);
    }
    private JSONObject findBest()throws Exception{
        List<Future<JSONObject>> futures=new ArrayList<>();
        for(int i=0;i<3;i++){
            final int p=i; futures.add(jobs.submit(()->probeProvider(p)));
        }
        JSONObject[] all=new JSONObject[3];
        for(int i=0;i<3;i++)all[i]=futures.get(i).get();
        int candidate=selected<3?selected:0;
        for(int i=0;i<3;i++)if(all[i].getInt("good")>all[candidate].getInt("good"))candidate=i;
        int count=all[candidate].getInt("good");
        if(count==0)return new JSONObject().put("selected",selected)
            .put("chosen",probeProvider(selected)).put("note","Нет подтверждённых HTTP 2xx — оставляем текущий DNS.");
        select(candidate);
        return new JSONObject().put("selected",selected).put("chosen",all[candidate])
            .put("note","Наибольшее число HTTP 2xx: "+DnsEngine.NAMES[candidate]+" ("+count+" из 6). Это не гарантирует доступ в сторонних приложениях.");
    }
    private synchronized void select(int p){
        selected=p;
        getPreferences(0).edit().putInt("selected",p).apply();
        DnsVpnService.setProvider(p);
    }
    private JSONObject checkUpdate(){
        JSONObject r=new JSONObject();
        try{
            HttpURLConnection c=(HttpURLConnection)new URL("https://api.github.com/repos/neiroseti-ai/hb-ai-xbox-dns/releases/latest").openConnection();
            c.setConnectTimeout(4000);c.setReadTimeout(4000);
            c.setRequestProperty("Accept","application/vnd.github+json");
            c.setRequestProperty("User-Agent","HB-AI-Android-1.24");
            if(c.getResponseCode()==200){
                byte[] data=new byte[32768];int n=c.getInputStream().read(data);if(n>0){
                    JSONObject release=new JSONObject(new String(data,0,n,StandardCharsets.UTF_8));
                    String tag=release.optString("tag_name","");
                    r.put("latest",tag);
                    r.put("url",release.optString("html_url","https://github.com/neiroseti-ai/hb-ai-xbox-dns/releases"));
                    r.put("newer",compareVersion(tag,"1.23")>0);
                }
            }
            c.disconnect();
        }catch(Exception ignored){}
        if(!r.has("newer"))try{r.put("newer",false);}catch(Exception ignored){}
        return r;
    }
    private static int compareVersion(String lhs,String rhs){
        String[] a=lhs.replaceAll("^[^0-9]*","").split("[^0-9]+");
        String[] b=rhs.split("\\.");
        for(int i=0;i<Math.min(3,Math.max(a.length,b.length));i++){
            try{
                int x=i<a.length?Integer.parseInt(a[i]):0,y=i<b.length?Integer.parseInt(b[i]):0;
                if(x!=y)return Integer.compare(x,y);
            }catch(Exception ignored){}
        }
        return 0;
    }
    private void requestVpn(){
        runOnUiThread(()->{
            try{
                Intent need=VpnService.prepare(this);
                if(need!=null)startActivityForResult(need,VPN_PERMISSION_REQUEST);
                else DnsVpnService.launch(this,DnsVpnService.START_VPN);
            }catch(Exception ex){DnsVpnService.error="Разрешение VPN: "+ex.getMessage();pushStatus();}
        });
    }
    @Override protected void onActivityResult(int request,int result,Intent data){
        super.onActivityResult(request,result,data);
        if(request==VPN_PERMISSION_REQUEST){
            if(result==RESULT_OK)DnsVpnService.launch(this,DnsVpnService.START_VPN);
            else DnsVpnService.error="Разрешение на DNS-VPN отклонено пользователем";
            pushStatus();
        }
    }
    private void complete(String id,JSONObject result,Exception error){
        String ok=result==null?"null":result.toString();
        String err=error==null?"null":JSONObject.quote(error.getMessage()==null?error.toString():error.getMessage());
        runOnUiThread(()->{if(web!=null)web.evaluateJavascript(
            "window.HBTransport&&HBTransport.complete("+JSONObject.quote(id)+","+JSONObject.quote(ok)+","+err+")",null);});
    }
    private class Bridge {
        @JavascriptInterface public void post(String id,String endpoint,String payload){
            if(id==null||id.length()>36||!id.matches("[a-zA-Z0-9_-]+")||endpoint==null)return;
            jobs.execute(()->{
                try{
                    JSONObject args=payload==null||payload.isEmpty()?new JSONObject():new JSONObject(payload);
                    JSONObject answer;
                    switch(endpoint){
                        case "status": answer=status();break;
                        case "select":{
                            int p=args.getInt("set");if(p<0||p>3)throw new Exception("Неверный DNS");
                            select(p);answer=status();break;
                        }
                        case "probe":{
                            int p=args.getInt("set");if(p<0||p>3)throw new Exception("Неверный DNS");
                            probeBusy=true;pushStatus();
                            try{answer=probeProvider(p);}finally{probeBusy=false;pushStatus();}
                            break;
                        }
                        case "best":{
                            probeBusy=true;pushStatus();
                            try{answer=findBest();}finally{probeBusy=false;pushStatus();}
                            break;
                        }
                        case "toggle":{
                            boolean on=args.getBoolean("on");
                            if(on){
                                if(!DnsVpnService.active()){
                                    if(rootAvailable){
                                        systemBusy=true;DnsVpnService.launch(MainActivity.this,DnsVpnService.START_ROOT);
                                    }else requestVpn();
                                }
                            }else{DnsVpnService.launch(MainActivity.this,DnsVpnService.STOP);}
                            answer=status();break;
                        }
                        case "verify":{
                            if("vpn".equals(DnsVpnService.mode)) {
                                long before=DnsVpnService.stats()[0];
                                String domain="hbai-"+Long.toHexString(System.nanoTime())+".example.org";
                                // A unique hostname avoids Android's DNS cache; NXDOMAIN is expected.
                                try{InetAddress.getAllByName(domain);}catch(Exception ignored){}
                                long after=DnsVpnService.stats()[0];
                                answer=new JSONObject().put("observed",after>before)
                                    .put("note",after>before?"Системный DNS-запрос действительно прошёл через VPN.":
                                    "VPN не получил DNS-запрос. Проверьте Private DNS, другой VPN и настройки сети.")
                                    .put("before",before).put("after",after);
                            } else {
                                answer=new JSONObject().put("observed",false)
                                    .put("note",DnsVpnService.active()?"В root-режиме собственные DNS-запросы приложения исключены из перехвата. Откройте сайт во внешнем приложении и проверьте счётчик.":
                                        "Сначала включите DNS-VPN.");
                            }
                            pushStatus();break;
                        }
                        case "root-check":{
                            rootAvailable=new RootController(MainActivity.this).available();rootChecked=true;
                            answer=new JSONObject().put("available",rootAvailable)
                                .put("details",rootAvailable?"Root-права получены. Будет использован root DNS.":
                                    "Root недоступен. Без root используется DNS-VPN Android без Termux.");
                            pushStatus();break;
                        }
                        case "open-settings":{
                            runOnUiThread(()->startActivity(new Intent("android.settings.WIRELESS_SETTINGS")));
                            answer=new JSONObject().put("opened",true);break;
                        }
                        case "update":answer=checkUpdate();break;
                        default: throw new Exception("Неизвестная операция");
                    }
                    complete(id,answer,null);
                }catch(Exception e){complete(id,null,e);}
            });
        }
        /** Never execute arbitrary native commands: only open a verified HTTP(S) URL in another app. */
        @JavascriptInterface public void open(String url){
            if(url==null||url.length()>2048||(!url.startsWith("https://")&&!url.startsWith("http://")))return;
            runOnUiThread(()->{try{startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse(url)));}catch(Exception ignored){}});
        }
    }
    @Override protected void onDestroy(){
        if(current.get()==this)current=new WeakReference<>(null);
        if(web!=null){web.removeJavascriptInterface("HBAndroid");web.destroy();web=null;}
        jobs.shutdownNow();probes.shutdownNow();super.onDestroy();
    }
}
