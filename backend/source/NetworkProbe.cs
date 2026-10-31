using System;
using System.Net;
using System.IO;
using System.Diagnostics;
class NetworkProbe {
  public static int Main(string[] args) {
    try {
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
      var req = (HttpWebRequest)WebRequest.Create("https://www.cloudflare.com/cdn-cgi/trace");
      req.Timeout=10000; req.ReadWriteTimeout=10000;
      req.Proxy = args.Length>0 && args[0]!="direct" ? new WebProxy(args[0]) : null;
      using(var resp=(HttpWebResponse)req.GetResponse())
      using(var reader=new StreamReader(resp.GetResponseStream())) {
        string text=reader.ReadToEnd(); string ip="";
        foreach(var line in text.Split('\n')) if(line.StartsWith("ip=")) ip=line.Substring(3).Trim();
        bool allowed=args.Length==2 && ip.Length>0 && Array.IndexOf(args[1].Split(','),ip)>=0;
        Console.WriteLine("HTTP="+(int)resp.StatusCode+" EXIT_ALLOWED="+allowed);
        return allowed ? 0 : 2;
      }
    } catch(WebException e) { Console.WriteLine("BLOCKED WebException "+e.Status);return 10; }
    catch(Exception e) { Console.WriteLine("BLOCKED "+e.GetType().Name);return 10; }
  }
}
