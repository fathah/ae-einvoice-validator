import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.*;
import javax.xml.XMLConstants;
import javax.xml.parsers.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;
import net.sf.saxon.lib.Feature;
import net.sf.saxon.s9api.*;
import org.w3c.dom.*;
import org.w3c.dom.ls.*;
import org.xml.sax.*;
import org.xml.sax.helpers.DefaultHandler;

/** Offline official UBL + PINT-AE validation. No document or error values are logged. */
public final class Validator {
  static final int MAX_XML = 8 * 1024 * 1024;
  static final String SPEC = "pint-ae-1.0.4";
  static final String MANIFEST = "9d241ecd1131545cba25c9719537f4e1f096ff02f82ab10f8ffe3acd22f7b13a";
  static final Map<String,String> HASHES = Map.of(
    "billing-resources.zip", "1e8b0bd595c672ac9d6fc886ddd0eb8027cb39a1d26bebdcb1ada37b7eee491f",
    "ubl21-schemas.zip", "e85dbd5f595a1dee8ad50ff6ce99fb376f9be94d43dfeafb897d5e1fdb0bde4c");
  static final String SVRL = "http://purl.oclc.org/dsdl/svrl";
  final Map<String,byte[]> schemas, billing;
  Validator(Path root) throws Exception {
    if (!digest(Files.readAllBytes(root.resolve("manifest.json"))).equals(MANIFEST)) throw new IOException("resource integrity");
    schemas = archive(root, "ubl21-schemas.zip"); billing = archive(root, "billing-resources.zip");
  }
  static String digest(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
  static Map<String,byte[]> archive(Path root,String name) throws Exception {
    byte[] bytes=Files.readAllBytes(root.resolve(name)); if(!digest(bytes).equals(HASHES.get(name))) throw new IOException("resource integrity");
    Map<String,byte[]> result=new HashMap<>(); int total=0;
    try(ZipInputStream zip=new ZipInputStream(new ByteArrayInputStream(bytes))) { ZipEntry entry;
      while((entry=zip.getNextEntry())!=null) { if(entry.isDirectory()) continue; String key=entry.getName();
        if(key.startsWith("/")||key.contains("..")||key.contains("\\")||result.containsKey(key)) throw new IOException("archive entry");
        byte[] value=zip.readNBytes(8*1024*1024+1); total+=value.length;
        if(value.length>8*1024*1024||total>32*1024*1024) throw new IOException("archive budget"); result.put(key,value);
      }
    } return Collections.unmodifiableMap(result);
  }
  static XMLReader reader() throws Exception {
    SAXParserFactory f=SAXParserFactory.newDefaultInstance();f.setNamespaceAware(true);f.setXIncludeAware(false);f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING,true);
    XMLReader r=f.newSAXParser().getXMLReader();
    r.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
    r.setFeature("http://xml.org/sax/features/external-general-entities",false);
    r.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
    r.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd",false);
    r.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD,"");r.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA,"");
    r.setEntityResolver((a,b)->{throw new SAXException("external resource denied");});
    r.setErrorHandler(new DefaultHandler(){public void error(SAXParseException e)throws SAXException{throw e;}public void fatalError(SAXParseException e)throws SAXException{throw e;}});
    return r;
  }
  static Document document(byte[] xml) throws Exception {
    if(xml.length<1||xml.length>MAX_XML)throw new IOException("input budget");
    XMLReader r=reader();r.setContentHandler(new DefaultHandler(){int nodes=0,depth=0;
      public void startElement(String uri,String local,String q,Attributes a)throws SAXException{if(++nodes>200000||++depth>64||a.getLength()>64)throw new SAXException("document budget");}
      public void endElement(String uri,String local,String q){depth--;}
      public void processingInstruction(String t,String d)throws SAXException{throw new SAXException("processing instruction denied");}
    });r.parse(new InputSource(new ByteArrayInputStream(xml)));
    DocumentBuilderFactory f=DocumentBuilderFactory.newDefaultInstance();f.setNamespaceAware(true);f.setXIncludeAware(false);f.setExpandEntityReferences(false);
    f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING,true);f.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
    f.setFeature("http://xml.org/sax/features/external-general-entities",false);f.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
    f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,"");f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA,"");
    javax.xml.parsers.DocumentBuilder b=f.newDocumentBuilder();b.setEntityResolver((a,c)->{throw new SAXException("external resource denied");});
    b.setErrorHandler(new DefaultHandler(){public void error(SAXParseException e)throws SAXException{throw e;}public void fatalError(SAXParseException e)throws SAXException{throw e;}});
    return b.parse(new ByteArrayInputStream(xml));
  }
  static final class LocalInput implements LSInput {
    final byte[] bytes; String id; LocalInput(byte[] b,String i){bytes=b;id=i;}
    public Reader getCharacterStream(){return null;} public void setCharacterStream(Reader v){}
    public InputStream getByteStream(){return new ByteArrayInputStream(bytes);}public void setByteStream(InputStream v){}
    public String getStringData(){return null;}public void setStringData(String v){}
    public String getSystemId(){return id;}public void setSystemId(String v){id=v;}
    public String getPublicId(){return null;}public void setPublicId(String v){}
    public String getBaseURI(){return id;}public void setBaseURI(String v){}
    public String getEncoding(){return "UTF-8";}public void setEncoding(String v){}
    public boolean getCertifiedText(){return false;}public void setCertifiedText(boolean v){}
  }
  boolean schema(Document doc,String kind) throws Exception {
    SchemaFactory f=SchemaFactory.newDefaultInstance();f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING,true);
    f.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD,"");f.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA,"");
    f.setResourceResolver((type,ns,pub,id,base)->{
      URI uri=URI.create(base).resolve(id).normalize();String prefix="https://wusooly.invalid/ubl/";
      if(!uri.toString().startsWith(prefix)||uri.getQuery()!=null||uri.getFragment()!=null)throw new IllegalStateException("external schema denied");
      byte[] bytes=schemas.get(uri.toString().substring(prefix.length()));if(bytes==null)throw new IllegalStateException("unknown schema");
      return new LocalInput(bytes,uri.toString());
    });
    String name="maindoc/UBL-"+kind+"-2.1.xsd";StreamSource source=new StreamSource(new ByteArrayInputStream(schemas.get(name)));source.setSystemId("https://wusooly.invalid/ubl/"+name);
    javax.xml.validation.Validator v=f.newSchema(source).newValidator();v.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD,"");v.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA,"");
    try {v.validate(new DOMSource(doc));return true;}catch(SAXException e){return false;}
  }
  static final class Assertions extends DefaultHandler {
    boolean root=false; long failures=0; final LinkedHashSet<String> rules=new LinkedHashSet<>();
    public void startElement(String uri,String local,String q,Attributes a){
      if(SVRL.equals(uri)&&"schematron-output".equals(local))root=true;
      if(SVRL.equals(uri)&&"failed-assert".equals(local)){failures++;String id=a.getValue("id");if(rules.size()<1000)rules.add(id!=null&&id.matches("[A-Za-z0-9._-]{1,128}")?id:"PINT-AE");}
    }
  }
  String validate(byte[] xml) throws Exception {
    String xmlDigest=digest(xml);Document doc;
    try{doc=document(xml);}catch(Exception e){return result(xmlDigest,false,0,List.of("XML-SAFETY"));}
    Element root=doc.getDocumentElement();String kind=root.getLocalName();
    if(!(kind.equals("Invoice")&&root.getNamespaceURI().equals("urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"))&&!(kind.equals("CreditNote")&&root.getNamespaceURI().equals("urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2")))return result(xmlDigest,false,0,List.of("UBL-DOCUMENT-TYPE"));
    if(!schema(doc,kind))return result(xmlDigest,false,0,List.of("UBL-XSD"));
    Processor processor=new Processor(false);processor.setConfigurationProperty(Feature.ALLOW_EXTERNAL_FUNCTIONS,false);processor.setConfigurationProperty(Feature.ALLOWED_PROTOCOLS,"");processor.setConfigurationProperty(Feature.DTD_VALIDATION,false);
    processor.getUnderlyingConfiguration().setResourceResolver(request->{throw new net.sf.saxon.trans.XPathException("external resource denied");});
    processor.getUnderlyingConfiguration().setUnparsedTextURIResolver((uri,encoding,config)->{throw new net.sf.saxon.trans.XPathException("external text denied");});
    processor.getUnderlyingConfiguration().setCollectionFinder((context,uri)->{throw new net.sf.saxon.trans.XPathException("external collection denied");});
    String prefix=kind.equals("Invoice")?"trn-invoice/schematron/":"trn-creditnote/schematron/";
    LinkedHashSet<String> failures=new LinkedHashSet<>();int executed=0;
    for(String name:List.of("PINT-UBL-validation-preprocessed.xslt","PINT-jurisdiction-aligned-rules.xslt")){
      byte[] stylesheet=billing.get(prefix+name);if(stylesheet==null)throw new IOException("rules unavailable");
      XsltCompiler compiler=processor.newXsltCompiler();compiler.setResourceResolver(request->{throw new net.sf.saxon.trans.XPathException("stylesheet resource denied");});
      InputSource input=new InputSource(new ByteArrayInputStream(stylesheet));input.setSystemId("urn:wusooly:official:"+name);
      XsltTransformer transform=compiler.compile(new SAXSource(reader(),input)).load();Assertions assertions=new Assertions();
      transform.setSource(new DOMSource(doc));transform.setDestination(new SAXDestination(assertions));transform.transform();
      if(!assertions.root)throw new IOException("rule output invalid");executed++;failures.addAll(assertions.rules);
    }
    return result(xmlDigest,true,executed,failures);
  }
  static String result(String digest,boolean xsd,int executed,Collection<String> rules){
    StringBuilder out=new StringBuilder("{\"specificationVersion\":\"").append(SPEC).append("\",\"resourceManifestDigest\":\"").append(MANIFEST).append("\",\"documentDigest\":\"").append(digest).append("\",\"xsdValid\":").append(xsd).append(",\"rulesExecuted\":").append(executed).append(",\"valid\":").append(xsd&&executed==2&&rules.isEmpty()).append(",\"failedRules\":[");
    boolean first=true;for(String rule:rules){if(!first)out.append(',');first=false;out.append('"').append(rule).append('"');}return out.append("]}").toString();
  }
  static byte[] bounded(InputStream input,int limit)throws IOException{byte[] value=input.readNBytes(limit+1);if(value.length>limit)throw new IOException("byte budget");return value;}
  static void respond(HttpExchange exchange,int status,byte[] bytes)throws IOException{exchange.getResponseHeaders().set("Content-Type","application/json");exchange.getResponseHeaders().set("Cache-Control","no-store");exchange.getResponseHeaders().set("X-Content-Type-Options","nosniff");exchange.sendResponseHeaders(status,bytes.length);try(OutputStream out=exchange.getResponseBody()){out.write(bytes);}}
  static final byte[] unavailable="{\"error\":\"validator_unavailable\"}".getBytes(StandardCharsets.UTF_8);
  static byte[] child(Path resources,byte[] xml)throws Exception{
    Process process=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","java").toString(),"-Xms32m","-Xmx384m","-cp",System.getProperty("java.class.path"),"Validator","--once",resources.toString()).redirectError(ProcessBuilder.Redirect.DISCARD).start();
    try(ExecutorService io=Executors.newVirtualThreadPerTaskExecutor()){
      Future<?> writer=io.submit(()->{try(OutputStream out=process.getOutputStream()){out.write(xml);}catch(IOException e){throw new UncheckedIOException(e);}});
      Future<byte[]> reader=io.submit(()->bounded(process.getInputStream(),128*1024));
      try{if(!process.waitFor(25,TimeUnit.SECONDS))throw new IOException("validation deadline");writer.get(1,TimeUnit.SECONDS);byte[] reply=reader.get(1,TimeUnit.SECONDS);if(process.exitValue()!=0||reply.length==0)throw new IOException("validation failed");return reply;}
      finally{process.destroyForcibly();process.getOutputStream().close();process.getInputStream().close();writer.cancel(true);reader.cancel(true);}
    }
  }
  public static void main(String[] args)throws Exception{
    Path resources=Path.of(args.length==2?args[1]:"/opt/app/resources").toAbsolutePath();Validator validator=new Validator(resources);
    if(args.length==2&&args[0].equals("--once")){byte[] xml=bounded(System.in,MAX_XML);System.out.print(validator.validate(xml));return;}
    if(args.length!=0&&!(args.length==2&&args[0].equals("--serve")))throw new IllegalArgumentException("unsupported arguments");
    String token=System.getenv("EINVOICE_VALIDATOR_TOKEN");if(token==null||!token.matches("[A-Za-z0-9._~-]{32,256}"))throw new IllegalStateException("validator authentication required");
    System.setProperty("sun.net.httpserver.drainAmount","0");System.setProperty("sun.net.httpserver.maxReqTime","30");System.setProperty("sun.net.httpserver.maxRspTime","30");System.setProperty("sun.net.httpserver.maxReqHeaders","32");System.setProperty("jdk.httpserver.maxConnections","32");
    HttpServer server=HttpServer.create(new InetSocketAddress("0.0.0.0",8081),16);Semaphore slots=new Semaphore(2);
    server.setExecutor(new ThreadPoolExecutor(4,4,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(16)));
    server.createContext("/",exchange->{try{
      if(exchange.getRequestURI().getRawQuery()!=null){respond(exchange,400,unavailable);return;}
      String path=exchange.getRequestURI().getPath();
      if((path.equals("/healthz")||path.equals("/v1/healthz"))&&exchange.getRequestMethod().equals("GET")){respond(exchange,200,("{\"specificationVersion\":\""+SPEC+"\",\"resourceManifestDigest\":\""+MANIFEST+"\"}").getBytes(StandardCharsets.UTF_8));return;}
      String authorization=exchange.getRequestHeaders().getFirst("Authorization");if(authorization==null||!MessageDigest.isEqual(authorization.getBytes(StandardCharsets.UTF_8),("Bearer "+token).getBytes(StandardCharsets.UTF_8))){respond(exchange,401,unavailable);return;}
      if(!(path.equals("/validate")||path.equals("/v1/validate"))||!exchange.getRequestMethod().equals("POST")){respond(exchange,404,unavailable);return;}
      if(!"application/xml".equals(exchange.getRequestHeaders().getFirst("Content-Type"))||exchange.getRequestHeaders().containsKey("Content-Encoding")||!SPEC.equals(exchange.getRequestHeaders().getFirst(path.equals("/v1/validate")?"X-Ziqx-Specification":"X-Wusooly-Specification"))){respond(exchange,415,unavailable);return;}
      String length=exchange.getRequestHeaders().getFirst("Content-Length");if(length!=null&&(Long.parseLong(length)<1||Long.parseLong(length)>MAX_XML)){respond(exchange,413,unavailable);return;}
      if(!slots.tryAcquire()){respond(exchange,503,unavailable);return;}
      try{byte[] xml=bounded(exchange.getRequestBody(),MAX_XML);respond(exchange,200,child(resources,xml));}finally{slots.release();}
    }catch(Exception ignored){try{respond(exchange,503,unavailable);}catch(IOException ignoredAgain){}}finally{exchange.close();}});
    Runtime.getRuntime().addShutdownHook(new Thread(()->server.stop(1)));server.start();
  }
}
