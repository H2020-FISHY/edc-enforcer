package ConverterXMItoXSD;

import java.io.IOException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xerces.dom.DeferredElementImpl;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import java.util.logging.*;

//si pu� aggiungere la possibilit� di generare le associazioni e le classi di associazioni, che per ora non vengono considerate
//genero un elemento root di una classe chiamata NSF

public class Converter {

    public static void main(String[] args) {

        String pathXMI = null;
        String outputPath = null;

        if (args.length == 2) {
            pathXMI = args[0];
            if(args[1].endsWith("/"))
                outputPath = args[1].concat("capability_data_model.xsd");
            else 
                outputPath = args[1];

        } else if (args.length == 1) {
            pathXMI = args[0];
            outputPath = "capability_data_model.xsd";
        } else {
            System.out.println("bad arguments error");
            return;
        }

        // System.out.println(pathXMI);
        // System.out.println(otuputPath);

        Document d = null;
        DocumentBuilderFactory df;
        DocumentBuilder builder;
        df = DocumentBuilderFactory.newInstance();
        XSDgenerator gen = new XSDgenerator();

        try {
            builder = df.newDocumentBuilder();
            d = builder.parse(pathXMI);

            // Element documentElement = d.getDocumentElement(); //contiene l'elemento
            // xmi:XMI
            // NodeList model = documentElement.getElementsByTagName("uml:Model");
            // //contiene l'elemento uml:Model, � di classe DeepNodeListImpl
            // Element elementoNodiInModel = (Element) model.item(0); //dato che model
            // contiene un elemento unico prendo quello e lo converto ad element
            // NodeList packagedElement =
            // elementoNodiInModel.getElementsByTagName("packagedElement"); //prendo gli
            // elementi che si chiamano "packagedElement" contenuti nel modello
            NodeList packagedElement = d.getElementsByTagName("packagedElement"); // si pu� sostituire coi quattro
                                                                                  // comandi sopra.
            // System.out.println(packagedElement.getLength());
            for (int i = 0; i < packagedElement.getLength(); i++) {
                if (packagedElement.item(i) instanceof DeferredElementImpl) {
                    Element element = (Element) packagedElement.item(i);
                    if (element.getAttribute("xmi:type").equalsIgnoreCase("uml:Class")) { // controllo se il
                                                                                          // packagedElement rappresenta
                                                                                          // una classe

                        Element complexType = gen.newElement("complexType"); // ne creo l'elemento
                        gen.addAttribute(complexType, "name", element.getAttribute("name")); // assegno il nome
                                                                                             // all'elemento
                        gen.addNewElement(complexType); // lo aggiungo al root

                        NodeList list = element.getChildNodes(); // prendo tutti i nodi figlio dell'elemento

                        Element general = null;
                        Element complexContent = null;
                        Element extension = null;
                        Element choice = null;
                        Element internalElement = null;
                        Element attribute = null;
                        Element attributeRef = null;

                        for (int j = 0; j < list.getLength(); j++) { // scorro tutti i figli per trovare le
                                                                     // caratteristiche che interessano
                            if (!(list.item(j) instanceof DeferredElementImpl)) { // fattibile solo includendo la
                                                                                  // libreria relativa
                                continue;
                            }
                            general = (Element) list.item(j); // creo un nuovo elemento per ogni figlio
                                                              // indipendentemente da che tipo sia, verr� analizzato con
                                                              // gli "if" dopo

                            if (list.item(j).getNodeName().equalsIgnoreCase("elementImport")) { // gestisco un element
                                                                                                // import
                                continue;
                            }

                            if (list.item(j).getNodeName().equalsIgnoreCase("ownedAttribute")) { // gestisco un element
                                                                                                 // ownedAttribute
                                if (general.getAttribute("name").equalsIgnoreCase("id")
                                        || general.getAttribute("name").equalsIgnoreCase("ref")) {
                                    if (general.getAttribute("name").equalsIgnoreCase("id")) {
                                        // System.out.println("capability " + element.getAttribute("name").toString());
                                        // System.out.println("name: " + general.getAttribute("name").toString());
                                        attribute = gen.newElement("attribute");
                                        gen.addAttribute(attribute, "name", general.getAttribute("name"));
                                        gen.addAttribute(attribute, "type", "xs:ID");
                                        // System.out.println("element: " + attribute.toString());
                                    } else {
                                        attributeRef = gen.newElement("attribute");
                                        gen.addAttribute(attributeRef, "name", general.getAttribute("name"));
                                        gen.addAttribute(attributeRef, "type", "xs:IDREF");
                                    }
                                } else if (general.getAttribute("name").equalsIgnoreCase("operator")) {
                                    attribute = gen.newElement("attribute");
                                    gen.addAttribute(attribute, "name", general.getAttribute("name"));
                                    if(element.getAttribute("name").contains("Condition"))
                                        gen.addAttribute(attribute, "type", "SupportedConditionOperatorEnumeration");
                                    else if(element.getAttribute("name").contains("Action"))
                                        gen.addAttribute(attribute, "type", "SupportedActionOperatorEnumeration");        
                                    Logger logger = Logger.getLogger(Converter.class.getName());
                                    logger.setLevel(Level.WARNING);
                                    logger.warning("ownedElement \"operator\" has been converted as attribute instead of element.");

                                } else {
                                    if (choice == null) { // se non esiste ancora la choice la creo altrimenti devo
                                                          // aggiungerlo alla stessa choice
                                        choice = gen.newElement("choice");
                                        gen.addAttribute(choice, "minOccurs", "0");
                                        gen.addAttribute(choice, "maxOccurs", "unbounded");
                                    }
                                    internalElement = gen.newElement("element");
                                    gen.addAttribute(internalElement, "name", general.getAttribute("name"));

                                    // aggiungo il tipo se esiste
                                    if (general.getAttribute("type") != "") { // cerco se esiste l'attributo type, vuol
                                                                              // dire che non � di tipo standard
                                        // System.out.println(general.getAttribute("type"));
                                        String s = findNameOfPackagedElementByIdandType(packagedElement,
                                                general.getAttribute("type"), "uml:Enumeration"); // controllo tra le
                                                                                                  // enumerazioni se
                                                                                                  // esiste questo tipo
                                        if (s == null) {
                                            s = findNameOfPackagedElementByIdandType(packagedElement,
                                                    general.getAttribute("type"), "uml:Class"); // controllo tra le
                                                                                                // classi se esiste
                                                                                                // questo tipo
                                            if (s == null) {
                                                System.out.println("no type definition found..... "
                                                        + general.getAttribute("type")); // se arrivo qui non ho trovato
                                                                                         // il tipo.. e non � gestito
                                                                                         // uscita di emergenza
                                            }
                                        }
                                        gen.addAttribute(internalElement, "type", s);
                                    }

                                    NodeList value = general.getChildNodes(); // prendo tutti i figli di general

                                    Element node = null;

                                    if (value.getLength() != 0) {
                                        boolean exist = false;
                                        // ho dei nodi interni
                                        for (int k = 0; k < value.getLength(); k++) {
                                            if (!(value.item(k) instanceof DeferredElementImpl)) { // fattibile solo
                                                                                                   // includendo la
                                                                                                   // libreria relativa
                                                continue;
                                            }
                                            node = (Element) value.item(k);
                                            String value1 = null;
                                            // System.out.println(node.getNodeName());
                                            // System.out.println(value.item(k).getNodeName());
                                            if (value.item(k).getNodeName().equalsIgnoreCase("defaultValue")) { // gestisco
                                                                                                                // il
                                                                                                                // default
                                                                                                                // value
                                                Element defaultValue = (Element) value.item(k);
                                                if (defaultValue.getAttribute("value") == "") {
                                                    continue;
                                                }
                                                String s = defaultValue.getAttribute("value"); // bisogna modificare le
                                                                                               // quot
                                                // System.out.println(s);
                                                if (s.contains("\"")) {
                                                    s = s.replace("\"", "");
                                                    // System.out.println("replacessato "+s);
                                                }
                                                gen.addAttribute(internalElement, "default", s);
                                            } else if (value.item(k).getNodeName().equalsIgnoreCase("lowerValue")) { // gestisco
                                                                                                                     // il
                                                                                                                     // lowerValue
                                                if (node.getAttribute("value") == "") {
                                                    value1 = "0";
                                                } else {
                                                    value1 = node.getAttribute("value");
                                                }

                                                gen.addAttribute(internalElement, "minOccurs", value1);
                                            } else if (value.item(k).getNodeName().equalsIgnoreCase("type")) { // gestisco
                                                                                                               // il
                                                                                                               // type
                                                if (node.getAttribute("xmi:type")
                                                        .equalsIgnoreCase("uml:PrimitiveType")) {
                                                    String href = node.getAttribute("href");
                                                    String[] split = href.split("#");
                                                    value1 = split[1];
                                                    if (value1.toLowerCase().contains("float")) {
                                                        value1 = "float";
                                                    }
                                                    value1 = "xs:" + value1.toLowerCase();
                                                }
                                                gen.addAttribute(internalElement, "type", value1);

                                            } else if (value.item(k).getNodeName().equalsIgnoreCase("upperValue")) { // gestisco
                                                                                                                     // il
                                                                                                                     // upperValue
                                                exist = true;
                                                if (node.getAttribute("value").equalsIgnoreCase("*")) {
                                                    value1 = "unbounded";
                                                } else if (node.getAttribute("value") != "") {
                                                    value1 = node.getAttribute("value").toString();
                                                } else {
                                                    value1 = "0"; // se viene indicato un uppervalue senza valore vuol
                                                                  // dire che � 0.
                                                }
                                                // System.out.println(value1);
                                                gen.addAttribute(internalElement, "maxOccurs", value1);
                                            }

                                        }
                                        if (!exist) {
                                            gen.addAttribute(internalElement, "maxOccurs", "1"); // se non esiste la
                                                                                                 // clausola upperValue
                                                                                                 // mette di default 1
                                        }

                                    }
                                    choice.appendChild(internalElement);
                                }
                                if (extension != null) {
                                    if (choice != null)
                                        extension.appendChild(choice);
                                    if (attribute != null)
                                        extension.appendChild(attribute);
                                    if (attributeRef != null)
                                        extension.appendChild(attributeRef);
                                } else {
                                    if (choice != null)
                                        complexType.appendChild(choice);
                                    if (attribute != null)
                                        complexType.appendChild(attribute);
                                    if (attributeRef != null)
                                        complexType.appendChild(attributeRef);
                                }

                                if(complexType.getAttribute("name").equals("RuleAttributeDetailsType")) {
                                    attribute = gen.newElement("attribute");
                                    gen.addAttribute(attribute, "name", "ref");
                                    gen.addAttribute(attribute, "type", "xs:string");
                                    complexType.appendChild(attribute); 
                                }

                                continue;
                            }

                            if (list.item(j).getNodeName().equalsIgnoreCase("generalization")) { // gestisco il
                                                                                                 // generalization

                                complexContent = gen.newElement("complexContent");
                                complexType.appendChild(complexContent);
                                extension = gen.newElement("extension");

                                String s = findNameOfPackagedElementByIdandType(packagedElement,
                                        general.getAttribute("general"), "uml:Class");
                                if (s == null) {
                                    return;
                                }

                                gen.addAttribute(extension, "base", s);

                                complexContent.appendChild(extension);

                                continue;
                            }
                        }
                    } else if (element.getAttribute("xmi:type").equalsIgnoreCase("uml:Enumeration")) { // controllo se
                                                                                                       // il
                                                                                                       // packagedElement
                                                                                                       // rappresenta
                                                                                                       // una
                                                                                                       // enumerazione
                        Element simpleType = gen.newElement("simpleType"); // ne creo l'elemento
                        gen.addAttribute(simpleType, "name", element.getAttribute("name"));
                        gen.addNewElement(simpleType);

                        NodeList list = element.getChildNodes(); // prendo tutti i nodi figlio dell'elemento

                        Element general = null;
                        Element restriction = null;

                        for (int j = 0; j < list.getLength(); j++) { // scorro tutti i figli per trovare le
                                                                     // caratteristiche che interessano
                            if (!(list.item(j) instanceof DeferredElementImpl)) { // fattibile solo includendo la
                                                                                  // libreria relativa
                                continue;
                            }
                            general = (Element) list.item(j); // creo un nuovo elemento per ogni figlio
                                                              // indipendentemente da che tipo sia, verr� analizzato con
                                                              // gli "if" dopo

                            if (list.item(j).getNodeName().equalsIgnoreCase("ownedLiteral")) { // quando incontro un
                                                                                               // figlio di questo tipo
                                                                                               // allora ho trovato un
                                                                                               // valore di questa
                                                                                               // enumerazione
                                if (restriction == null) {
                                    restriction = gen.newElement("restriction");
                                    gen.addAttribute(restriction, "base", "xs:string");
                                    simpleType.appendChild(restriction);
                                }
                                Element enumeration = gen.newElement("enumeration");
                                gen.addAttribute(enumeration, "value", general.getAttribute("name"));
                                restriction.appendChild(enumeration);

                            }
                        }
                    }
                }
            }

        } catch (ParserConfigurationException e) {
            System.out.println("Error: " + e.getMessage());
            return;
        } catch (SAXException e) {
            System.out.println("Error: " + e.getMessage());
            return;
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
            return;
        }

        Element root = gen.newElement("element"); // genero l'elemento root, nsf
        root.setAttribute("name", "nsfCatalogue");
        root.setAttribute("type", "NSFCatalogue");
        gen.addNewElement(root);

        if (gen.transform(outputPath)) {
            System.out.println("XMI converted to XSD.");
        }

    }

    public static String findNameOfPackagedElementByIdandType(NodeList nl, String id, String classe) {
        for (int i = 0; i < nl.getLength(); i++) {
            Element element = (Element) nl.item(i);
            if (element.getAttribute("xmi:type").equalsIgnoreCase(classe)
                    && element.getAttribute("xmi:id").equals(id)) {
                // System.out.println(id+" "+element.getAttribute("name"));
                return element.getAttribute("name");
            }
        }
        return null;

    }

}