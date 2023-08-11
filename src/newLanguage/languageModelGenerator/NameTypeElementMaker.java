package languageModelGenerator;

import javax.xml.XMLConstants;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class NameTypeElementMaker {
    private String nsPrefix;
    private Document doc;

    public NameTypeElementMaker(String nsPrefix, Document doc) {
        this.nsPrefix = nsPrefix;
        this.doc = doc;
    }

    public Element createElement(String elementName) {
        return doc.createElementNS(XMLConstants.W3C_XML_SCHEMA_NS_URI, nsPrefix + elementName);
    }

    public void setAttribute(Element element, String nameAttr, String attrValue) {

        //controllo se gli elementi che hanno come attributo "base" o "type", in caso splitto la parte di prefix perch� generando un unico xsd non servono reindirizzamenti
        //ma non devo modificare gli attributi che si riferiscono a tipi di "xs:" ad esempio xs:string
        if ((nameAttr.equals("base") || nameAttr.equals("type")) && !attrValue.contains("xs:")) {
            if (attrValue.contains(":")) {
                String[] tagName = attrValue.split(":");
                //String prefix = tagName[0];													
                attrValue = tagName[1];
            }
        }

        element.setAttribute(nameAttr, attrValue);
        return;
    }

}