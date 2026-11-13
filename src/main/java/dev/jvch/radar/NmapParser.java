package dev.jvch.radar;

import dev.jvch.radar.Model.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/** Reads nmap -oX output. Scan files come from third parties, so DOCTYPEs are refused outright. */
public final class NmapParser {
    public static final int MAX_BYTES = 64 * 1024 * 1024;

    private NmapParser() {}

    public static Scan parse(String xml) {
        if (xml.length() > MAX_BYTES) throw new IllegalArgumentException("scan file is larger than 64 MiB");
        Document doc;
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setXIncludeAware(false);
            f.setExpandEntityReferences(false);
            javax.xml.parsers.DocumentBuilder db = f.newDocumentBuilder();
            db.setErrorHandler(new org.xml.sax.helpers.DefaultHandler() {
                @Override public void error(org.xml.sax.SAXParseException e) throws org.xml.sax.SAXException { throw e; }
                @Override public void fatalError(org.xml.sax.SAXParseException e) throws org.xml.sax.SAXException { throw e; }
            });
            doc = db.parse(new InputSource(new StringReader(xml)));
        } catch (Exception e) {
            String m = e.getMessage() == null ? e.toString() : e.getMessage();
            throw new IllegalArgumentException("not a valid nmap XML file: " + m.split("\n")[0]);
        }
        Element root = doc.getDocumentElement();
        if (!"nmaprun".equals(root.getTagName())) throw new IllegalArgumentException("not an nmap XML file (root element is " + root.getTagName() + ")");
        Instant start = Instant.EPOCH;
        String s = root.getAttribute("start");
        if (!s.isEmpty()) {
            try { start = Instant.ofEpochSecond(Long.parseLong(s)); } catch (NumberFormatException ignored) { /* keep epoch */ }
        }
        List<Host> hosts = new ArrayList<>();
        for (Element h : kids(root, "host")) {
            Element status = first(h, "status");
            if (status != null && !status.getAttribute("state").equals("up")) continue;
            String addr = null;
            for (Element a : kids(h, "address")) {
                String t = a.getAttribute("addrtype");
                if (t.equals("ipv4") || t.equals("ipv6")) { addr = a.getAttribute("addr"); if (t.equals("ipv4")) break; }
            }
            if (addr == null) continue;
            String name = "";
            Element hn = first(h, "hostnames");
            if (hn != null) { Element n = first(hn, "hostname"); if (n != null) name = n.getAttribute("name"); }
            List<Port> ports = new ArrayList<>();
            Element ps = first(h, "ports");
            if (ps != null) for (Element p : kids(ps, "port")) {
                Port port = port(p);
                if (port != null) ports.add(port);
            }
            hosts.add(new Host(addr, name, ports));
        }
        return new Scan(start, hosts);
    }

    private static Port port(Element p) {
        int num;
        try { num = Integer.parseInt(p.getAttribute("portid")); } catch (NumberFormatException e) { return null; }
        if (num < 0 || num > 65535) return null;
        Element st = first(p, "state");
        String state = st == null ? "unknown" : st.getAttribute("state");
        Element sv = first(p, "service");
        String service = sv == null ? null : sv.getAttribute("name");
        String product = sv == null ? null : sv.getAttribute("product");
        String version = sv == null ? null : sv.getAttribute("version");
        Cert cert = null;
        List<String> tls = new ArrayList<>();
        for (Element sc : kids(p, "script")) {
            String id = sc.getAttribute("id");
            if (id.equals("ssl-cert")) cert = cert(sc);
            else if (id.equals("ssl-enum-ciphers")) {
                for (Element t : kids(sc, "table")) {
                    String k = t.getAttribute("key");
                    if (k.startsWith("TLSv") || k.startsWith("SSLv")) tls.add(k);
                }
            }
        }
        return new Port(num, p.getAttribute("protocol"), state, service, product, version, cert, tls);
    }

    private static Cert cert(Element script) {
        String subject = null, issuer = null;
        Instant nb = null, na = null;
        for (Element t : kids(script, "table")) {
            String k = t.getAttribute("key");
            if (k.equals("subject")) subject = elem(t, "commonName");
            else if (k.equals("issuer")) issuer = elem(t, "commonName");
            else if (k.equals("validity")) { nb = time(elem(t, "notBefore")); na = time(elem(t, "notAfter")); }
        }
        return subject == null && na == null ? null : new Cert(subject, issuer, nb, na);
    }

    private static Instant time(String s) {
        if (s == null) return null;
        try { return LocalDateTime.parse(s.replace(' ', 'T').replaceAll("Z$", "")).toInstant(ZoneOffset.UTC); }
        catch (DateTimeParseException e) { return null; }
    }

    private static String elem(Element parent, String key) {
        for (Element e : kids(parent, "elem")) if (e.getAttribute("key").equals(key)) return e.getTextContent().trim();
        return null;
    }

    private static Element first(Element p, String tag) {
        List<Element> k = kids(p, tag);
        return k.isEmpty() ? null : k.get(0);
    }

    private static List<Element> kids(Element p, String tag) {
        List<Element> out = new ArrayList<>();
        NodeList nl = p.getChildNodes();
        for (int i = 0; i < nl.getLength(); i++) {
            Node n = nl.item(i);
            if (n instanceof Element e && e.getTagName().equals(tag)) out.add(e);
        }
        return out;
    }
}
