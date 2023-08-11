package languageModelGenerator;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

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

import org.apache.xerces.dom.DeferredElementImpl;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class XSDgenerator {

    private final static String NS_PREFIX = "xs:";

    private TreeSet < String > capability = new TreeSet < String > ();
    private List < String > type = new ArrayList < String > ();

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

        this.doc.appendChild(this.schemaRoot);
    }

    //funzione che aggiunge un nuovo elemento alla root dello schema da generare partendo da un elemento letto da un altro XSD
    public void addElement(Element e) {
        //l'element che arriva in questo punto � sicuramente un xs:complexType
        // System.out.println("nome in add element "+e.getAttribute("name"));
        if (capabilityInListYet(e.getAttribute("name"))) {
            return;
        } else {
            addCapaInList(e.getAttribute("name"));
            Element daInserire = createElementRecursively(e);
            if (daInserire != null) {
                this.schemaRoot.appendChild(daInserire);
            }

        }
    }

    //genera ricorsivamente tutti gli elementi interni all'elemento da aggiungere alla root
    public Element createElementRecursively(Element e) {
        String name;

        if (e.getTagName().contains(":")) {
            String[] tagName = e.getTagName().split(":");
            //String prefix = tagName[0];													
            name = tagName[1];
        } else {
            name = e.getTagName();
        }
        if (e.getAttribute("name").equalsIgnoreCase("adapter")) { //generando il linguaggio devo evitare di mettere l'attributo "adapter", perch� serve solo nelle istanze dal modello delle capability all'nsf; ma in questo modo se non ho altri attributi nella classe "securityCapability" genera comunque <sequence/>
            return null;
        }

        if (e.getAttribute("name").equalsIgnoreCase("languageGeneratorConstraint")) { //generando il linguaggio devo evitare di mettere l'attributo "translator", perch� serve solo nelle istanze dal modello delle capability all'nsf; ma in questo modo se non ho altri attributi nella classe "securityCapability" genera comunque <sequence/>
            return null;
        }
        Element daInserire = elMaker.createElement(name);
        insertAllAttributes(e, daInserire);

        if (!e.hasChildNodes()) {
            return daInserire;
        }
        NodeList nodes = e.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            if (!(nodes.item(i) instanceof DeferredElementImpl)) { //fattibile solo includendo la libreria relativa 
                continue;
            }
            Element ne = (Element) nodes.item(i);
            Element ne2 = createElementRecursively(ne);
            if (ne2 != null)
                daInserire.appendChild(ne2);
        }
        return daInserire;
    }

    //funzione che genera effettivamente l'output relativo al nuovo xsd
    public boolean transform(String outputName) {

        try {

            TransformerFactory tFactory = TransformerFactory.newInstance();
            Transformer transformer = tFactory.newTransformer();
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            DOMSource domSource = new DOMSource(this.doc);
            File f = new File(outputName); 
            if(outputName.contains("/"))
                f.getParentFile().mkdirs();
            transformer.transform(domSource, new StreamResult(f));

        } catch (FactoryConfigurationError | TransformerException e) {
            //handle exception
            System.out.println("Error: " + e.getMessage());
            return false;
        }
        return true;

    }

    //funzione che cicla e fa aggiungere tutti gli attributi di un elemento
    public void insertAllAttributes(Element fromElement, Element toElement) {
        NamedNodeMap attributes = fromElement.getAttributes();
        for (int i = 0; i < attributes.getLength(); i++) {
            Node n = attributes.item(i);
            this.elMaker.setAttribute(toElement, n.getNodeName(), n.getNodeValue());
            if (n.getNodeName().equalsIgnoreCase("type") && !n.getNodeValue().contains("xs:")) {
                this.type.add(n.getNodeValue());
            }
        }
        return;
    }

    //funzione che aggiunge il nome di una capability alla lista delle capability esistenti
    public void addCapaInList(String s) {
        this.capability.add(s);
    }

    //funzione che ritorna se la capability passata come stringa � gi� stata generata
    public boolean capabilityInListYet(String s) {
        if (this.capability.contains(s)) {
            return true;
        } else {
            return false;
        }
    }

    //funzione che cicla su tutti i tipi di complexType/basicTypes incontrati e ne genera l'elemento nell'xsd di output
    public void generateType(NodeList typeComplex) {
        for (int i = 0; i < typeComplex.getLength(); i++) {
            Element typeItem = (Element) typeComplex.item(i);
            //System.out.println(typeItem.getAttribute("name"));
            for (int j = 0; j < this.type.size(); j++) {
                if (this.type.get(j).contains(typeItem.getAttribute("name"))) {
                    // System.out.println(typeItem.getAttribute("name"));
                    addElement(typeItem);
                }
            }
        }
    }

    //genera un elemento nuovo, passando il nome dell'elemento inserendo il prefisso che � stato deciso
    public Element newElement(String name) {
        return elMaker.createElement(name);
    }

    //funzione che passato un elemento gli aggiunge l'attributo passato con il valore passato
    public void addAttribute(Element element, String nameAttr, String attrValue) {
        this.elMaker.setAttribute(element, nameAttr, attrValue);
    }

    //funzione che aggiunge un nuovo elemento alla root dello schema da generare partendo da un elemento letto da un altro XSD
    public void addNewElement(Element e) {
        //Element daInserire = createElementRecursively (e);
        this.schemaRoot.appendChild(e);
    }

    public void addEnumerationFromList(String name, List < String > valueList) {
        if (capabilityInListYet(name)) {
            return;
        } else {
            addCapaInList(name);
        }
        Element simpleType = this.elMaker.createElement("simpleType");
        simpleType.setAttribute("name", name);
        Element restriction = this.elMaker.createElement("restriction");
        restriction.setAttribute("base", "xs:string");
        for (int i = 0; i < valueList.size(); i++) {
            Element enumeration = this.elMaker.createElement("enumeration");
            enumeration.setAttribute("value", valueList.get(i));
            restriction.appendChild(enumeration);
        }
        simpleType.appendChild(restriction);
        addNewElement(simpleType);

    }

    //genera un simple type di integerRestriction utilizzando i valori nella NodeList 
    //utilizzando la capability in posizione 0 della lista e assegnando agli attributi nella lista il tipo appena creato
    public void addNewSimpleTypeIntegerRestrictionFromNodeList(List < String > capabilityAndAttributesToBeChanged, NodeList setNumericRangeNodeList) {
        Element simpleType = this.elMaker.createElement("simpleType");

        if (capabilityAndAttributesToBeChanged.size() < 2) {
            System.out.println("Error wrong size Capability or Attributes to be changed");
            return;
        }

        simpleType.setAttribute("name", capabilityAndAttributesToBeChanged.get(0) + "IntegerRestriction");
        Element union = this.elMaker.createElement("union");
        for (int i = 0; i < setNumericRangeNodeList.getLength(); i++) {

            Element simpleType2 = this.elMaker.createElement("simpleType");
            Element restriction = this.elMaker.createElement("restriction");
            restriction.setAttribute("base", "xs:integer");
            Element formElement = this.elMaker.createElement("minInclusive");
            formElement.setAttribute("value", ((Element) setNumericRangeNodeList.item(i)).getElementsByTagName("from").item(0).getTextContent());
            Element toElement = this.elMaker.createElement("maxInclusive");
            toElement.setAttribute("value", ((Element) setNumericRangeNodeList.item(i)).getElementsByTagName("to").item(0).getTextContent());
            restriction.appendChild(formElement);
            restriction.appendChild(toElement);
            simpleType2.appendChild(restriction);
            union.appendChild(simpleType2);
        }
        simpleType.appendChild(union);
        addNewElement(simpleType);

        changeElementTypeInExistingComplexType(capabilityAndAttributesToBeChanged, capabilityAndAttributesToBeChanged.get(0) + "IntegerRestriction");
    }

    //questa funzione cerca la capability i cui attributi sono stati modificati e li modifica anche nel oggetto che verr� utilizzato per la generazione dell'XSD
    private void changeElementTypeInExistingComplexType(List < String > capabilityAndAttributesToBeChanged, String newTypeName) {
        NodeList allActualComplexType = this.schemaRoot.getElementsByTagName("xs:complexType"); //prendo tutti i complex type che ho generato fin ora
        for (int i = 0; i < allActualComplexType.getLength(); i++) {
            Element capaToBeChanged = (Element) allActualComplexType.item(i);
            if (capaToBeChanged.getAttribute("name").contentEquals(capabilityAndAttributesToBeChanged.get(0))) { //controllo se � esattamente quel type che mi interessa
                NodeList internalElementNodeList = capaToBeChanged.getElementsByTagName("xs:element"); //prendo la lista degli attributi/elementi che possiede
                for (int j = 0; j < internalElementNodeList.getLength(); j++) {
                    Element internalElement = (Element) internalElementNodeList.item(j);
                    //System.out.println(internalElement.getAttribute("name"));
                    //System.out.println(capabilityAndAttributesToBeChanged);
                    if (capabilityAndAttributesToBeChanged.contains(internalElement.getAttribute("name"))) { //controllo se questi elementi hanno il nome di quelli da essere cambiati
                        internalElement.setAttribute("type", newTypeName);
                    }
                }
            }
        }
    }

    //funzione che genera una nuova restrizione intera chiamandola come il primo nome contenuto nella lista +"IntegerRestriction" 
    //e cambia a tutti gli attributi passati nella lista il tipo mettendoci quello appena generato
    //la lista degli interi � generata dai valori della mappa passata
    public void generateIntegerMatchingFromMatchingNumbers(List < String > capabilityAndAttributesToBeChanged, Map < String, Integer > nameValueMapSortedByIntegerValue) {

        if (capabilityAndAttributesToBeChanged.size() < 2) {
            System.out.println("Error wrong size Capability or Attributes to be changed");
            return;
        }

        Element simpleType = this.elMaker.createElement("simpleType");
        simpleType.setAttribute("name", capabilityAndAttributesToBeChanged.get(0) + "IntegerRestriction");
        Element union = this.elMaker.createElement("union");
        Set < Integer > integerSetPresent = new TreeSet < Integer > ();
        for (String key: nameValueMapSortedByIntegerValue.keySet()) { //cos� si fa una union per ogni numero

            if (!integerSetPresent.add(nameValueMapSortedByIntegerValue.get(key))) { //permette di togliere i doppioni
                continue;
            }

            Element simpleType2 = this.elMaker.createElement("simpleType");
            Element restriction = this.elMaker.createElement("restriction");
            restriction.setAttribute("base", "xs:integer");
            Element formElement = this.elMaker.createElement("minInclusive");
            formElement.setAttribute("value", nameValueMapSortedByIntegerValue.get(key).toString());
            Element toElement = this.elMaker.createElement("maxInclusive");
            toElement.setAttribute("value", nameValueMapSortedByIntegerValue.get(key).toString());
            restriction.appendChild(formElement);
            restriction.appendChild(toElement);
            simpleType2.appendChild(restriction);
            union.appendChild(simpleType2);
        }
        simpleType.appendChild(union);
        addNewElement(simpleType);

        changeElementTypeInExistingComplexType(capabilityAndAttributesToBeChanged, capabilityAndAttributesToBeChanged.get(0) + "IntegerRestriction");

    }

    //funzione che genera una nuova restrizione intera chiamandola come il primo nome contenuto nella lista +"IntegerRestriction" 
    //e cambia a tutti gli attributi passati nella lista il tipo mettendoci quello appena generato
    //la lista dei valori interi che saranno generati � contenuta nella NodeList
    public void newIntegerRestrictedSimpleType(NodeList setNumericRangeNodeList,
        List < String > capabilityAndAttributesToBeChanged) {
        if (capabilityAndAttributesToBeChanged.size() < 2) {
            System.out.println("Error wrong Capability or Attributes to be changed");
            return;
        }

        Element simpleType = this.elMaker.createElement("simpleType");
        simpleType.setAttribute("name", capabilityAndAttributesToBeChanged.get(0) + "IntegerRestriction");
        Element union = this.elMaker.createElement("union");

        for (int i = 0; i < setNumericRangeNodeList.getLength(); i++) {
            Element integerRange = (Element) setNumericRangeNodeList.item(i);
            Element simpleType2 = this.elMaker.createElement("simpleType");
            Element restriction = this.elMaker.createElement("restriction");
            restriction.setAttribute("base", "xs:integer");
            Element formElement = this.elMaker.createElement("minInclusive");
            formElement.setAttribute("value", ((Element) integerRange.getElementsByTagName("from").item(0)).getTextContent());
            Element toElement = this.elMaker.createElement("maxInclusive");
            toElement.setAttribute("value", ((Element) integerRange.getElementsByTagName("to").item(0)).getTextContent());
            restriction.appendChild(formElement);
            restriction.appendChild(toElement);
            simpleType2.appendChild(restriction);
            union.appendChild(simpleType2);
        }

        simpleType.appendChild(union);
        addNewElement(simpleType);

        changeElementTypeInExistingComplexType(capabilityAndAttributesToBeChanged, capabilityAndAttributesToBeChanged.get(0) + "IntegerRestriction");

    }

    //questa funzione cerca la capability tra quelle già aggiunte
    public Element getExistingComplexType(String capabilityName) {
        NodeList allActualComplexType = this.schemaRoot.getElementsByTagName("xs:complexType"); //prendo tutti i complex type che ho generato fin ora
        for (int i = 0; i < allActualComplexType.getLength(); i++) {
            Element capability = (Element) allActualComplexType.item(i);
            if (capability.getAttribute("name").contentEquals(capabilityName)) { //controllo se � esattamente quel type che mi interessa
                return capability;
            }
        }
        return null;
    }

}