package ConverterXMItoXSD;

import java.io.File;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.XMLConstants;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class XSDgenerator {

    private final static String NS_PREFIX = "xs:";

    private DocumentBuilderFactory docBuilderFactory;
    private DocumentBuilder docBuilder;
    private Document doc;
    private Element schemaRoot;
    private NameTypeElementMaker elMaker;

    //costruttore
    public XSDgenerator() {
        this.docBuilderFactory = DocumentBuilderFactory.newInstance();
        try {
            this.docBuilder = this.docBuilderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            System.out.println("Error: " + e.getMessage());
            return;
        }
        this.doc = this.docBuilder.newDocument();
        this.schemaRoot = this.doc.createElementNS(XMLConstants.W3C_XML_SCHEMA_NS_URI, NS_PREFIX + "schema");
        this.elMaker = new NameTypeElementMaker(NS_PREFIX, this.doc);

        this.doc.appendChild(schemaRoot);
    }

    //funzione che genera effettivamente l'output relativo al nuovo xsd
    public boolean transform(String outputName) {

        this.elMaker.setAttribute(this.schemaRoot, "xmlns", "http://untitled/" + outputName);
        this.elMaker.setAttribute(this.schemaRoot, "targetNamespace", "http://untitled/" + outputName);

        try {

            TransformerFactory tFactory = TransformerFactory.newInstance();
            Transformer transformer = tFactory.newTransformer();
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            DOMSource domSource = new DOMSource(this.doc);
            transformer.transform(domSource, new StreamResult(new File(outputName)));
            //printa su console
            //transformer.transform(domSource, new StreamResult(System.out));

        } catch (FactoryConfigurationError | TransformerException e) {
            //handle exception
            System.out.println("Error: " + e.getMessage());
            return false;
        }
        return true;

    }

    //genera un elemento nuovo, passando il nome dell'elemento inserendo il prefisso che � stato deciso
    public Element newElement(String name) {
        return this.elMaker.createElement(name);
    }

    public void addAttribute(Element element, String nameAttr, String attrValue) {
        this.elMaker.setAttribute(element, nameAttr, attrValue);
    }

    //funzione che aggiunge un nuovo elemento alla root dello schema da generare partendo da un elemento letto da un altro XSD
    public void addNewElement(Element e) {
        this.schemaRoot.appendChild(e);
    }

}