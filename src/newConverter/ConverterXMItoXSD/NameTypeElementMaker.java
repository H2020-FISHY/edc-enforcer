package ConverterXMItoXSD;

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
        return doc.createElementNS(XMLConstants.W3C_XML_SCHEMA_NS_URI, nsPrefix+elementName);
    }
    
    public void setAttribute(Element element, String nameAttr, String attrValue) {
    	element.setAttribute(nameAttr, attrValue);
    	return;
    }
    
    
}
