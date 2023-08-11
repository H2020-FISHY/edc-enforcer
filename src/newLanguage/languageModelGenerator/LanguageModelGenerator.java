package languageModelGenerator;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xerces.dom.DeferredElementImpl;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import validatore.Validatore;

public class LanguageModelGenerator {
    private String xsd, xml, nsfName, outputName;
    private List < String > imports;
    private List < NodeList > complexTypeNodeLists;
    private List < NodeList > simpleTypeNodeLists;
    private XSDgenerator gen;
    private List < String > metadataPath; //conterr� i path verso i metadati di quell'nsf

    public LanguageModelGenerator(String xsd, String xml, String nsfName, String outputName) {
        //System.out.println(xsd+" "+xml);
        this.xsd = xsd;
        this.xml = xml;
        this.nsfName = nsfName;
        this.complexTypeNodeLists = new ArrayList < NodeList > ();
        this.imports = new ArrayList < String > ();
        this.imports.add(xsd);
        this.simpleTypeNodeLists = new ArrayList < NodeList > ();
        this.outputName = outputName;
        this.gen = new XSDgenerator();
        this.metadataPath = new ArrayList < String > ();
    }

    public static void main(String[] args) {

        /*String pathXSD = "capability_data_model.xsd";
        String pathXML = "NSFCatalogue.xml";
        String otuputPath = "language.xsd";
        String nsfName = "XFRM";*/

        String pathXSD = null;
        String pathXML = null;
        String nsfName = null;
        String outputPath = null;

        if (args.length == 4) {
            pathXSD = args[0];
            pathXML = args[1];
            nsfName = args[2];
            if(args[3].endsWith("/"))
                outputPath = args[3].concat("language_" + nsfName + ".xsd");
            else 
                outputPath = args[3];
        } else if (args.length == 3) {
            pathXSD = args[0];
            pathXML = args[1];
            nsfName = args[2];
            outputPath = "language_" + nsfName + ".xsd";
        } else {
            System.out.println("bad arguments error");
            return;
        }

        LanguageModelGenerator par = new LanguageModelGenerator(pathXSD, pathXML, nsfName, outputPath);
        if (par.generateLanguage()) {
            System.out.println(nsfName + " language generated");
        }

    }

    public boolean validate() {
        Validatore v = new Validatore(this.xsd, this.xml);
        if (!v.validate()) {
            System.out.println("the instance is invalid");
            return false;
        }
        return true;
    }

    //classe che genera il file xsd del linguaggio relativo alle istanze dell'xml validato rispetto all'xsd generato dal modello di modelio
    public boolean generateLanguage() {

        if (!validate()) {
            return false;
        }

        this.imports.addAll(getAllImportPaths()); //prende tutti gli import specificati nel file principale, questo permette di avere in input xsd divisi.

        //ricevo lista con per ogni istanza i nodi contenenti tutti i coplexType di ogni file di cui � composto l'xsd
        this.complexTypeNodeLists = getAllNodelistFromImportsByTagName(this.imports, "xs:complexType");
        if (this.complexTypeNodeLists == null) {
            System.out.println("node list error");
            return false;
        }
        this.simpleTypeNodeLists = getAllNodelistFromImportsByTagName(this.imports, "xs:simpleType");
        if (this.simpleTypeNodeLists == null) {
            System.out.println("node list error");
            return false;
        }
        Document d = generateDocument(this.xml);
        if (d == null) {
            System.out.println(this.xml + " document not found");
            return false;
        }

        NodeList nsfList = getNodelistOfElementFromDocumentByTagname(d, "nSF");
        NodeList refSecCapList = null;
        for (int i = 0; i < nsfList.getLength(); i++) {
            String idNSF = idSecurityCapability((Element) nsfList.item(i));
            //System.out.println(idNSF);
            if (idNSF != null) {
                if (nsfName.equalsIgnoreCase(idNSF)) {
                    refSecCapList = nsfList.item(i).getChildNodes();
                }
            }
        }
        /*for(int i=0; i<refSecCapList.getLength(); i++){
        	if(!(refSecCapList.item(i) instanceof DeferredElementImpl)) { 								//fattibile solo includendo la libreria relativa 
        		continue;
        	}
        	System.out.println(refSecurityCapability((Element)refSecCapList.item(i)));
        }*/
        if (refSecCapList.getLength() <= 0) {
            System.out.println("NSF node list error");
            return false;
        }

        NodeList securityCapabilityList = getNodelistOfElementFromDocumentByTagname(d, "securityCapability"); //ricevo i nodi contenenti tutti i securityCapability del file di input
        String[] baseNewSecCapList = new String[securityCapabilityList.getLength()]; //lista dove inserire tutti i base trovati
        String[] nameNewSecCapList = new String[securityCapabilityList.getLength()]; //lista dove inserire tutti i name trovati
        String nameNewSecCap = null; //variabile di supporto dove appoggiarsi per scorrere i name delle SecCap
        String baseNewSecCap = null; //variabile di supporto dove appoggiarsi per scorrere i base delle SecCap
        int index = 0;

        NodeList languageGenerationList = getNodelistOfElementFromDocumentByTagname(d, "languageGenerationDetails");
        List < Element > translatorConstraintsList = new ArrayList < Element > ();

        Element found = null;
        //bisonga aggiungere l'elemento concreto di root per creare una root nel nuovo xsd, lo faccio statico in modo da uniformare gli output 
        //dato che aggiungo una classe intermedia che funziona da rule
        Element elem = this.gen.newElement("element"); //qui definisco l'elemento totale, l'nsf
        elem.setAttribute("name", "policy");
        elem.setAttribute("type", "Policy");
        this.gen.addNewElement(elem);

        //genero il nuovo complex type Policy																			//definisco la classe nsf
        elem = this.gen.newElement("complexType");
        this.gen.addAttribute(elem, "name", "Policy");
        Element seq = this.gen.newElement("sequence");
        elem.appendChild(seq);

        Element ele = this.gen.newElement("element"); //elemento che da il nome all'istanza	
        this.gen.addAttribute(ele, "maxOccurs", "unbounded");
        this.gen.addAttribute(ele, "minOccurs", "0");
        this.gen.addAttribute(ele, "name", "rule");
        this.gen.addAttribute(ele, "type", "Rule");
        
        seq.appendChild(ele);

        /**
         * Si aggiunge l'elemento defaultActionCapability nel nodo policy, 
         * se presente tra le Security Capability della NSF in questione
         * in questo modo è possibile indicarlo in seguito 
         * alle rule espresse in RuleInstance
         */ 
        if(isSecurityCapabilityInList(refSecCapList, "defaultActionCapabilitySpec")) {
            ele = this.gen.newElement("element"); //elemento che da il nome all'istanza	
            this.gen.addAttribute(ele, "maxOccurs", "1");
            this.gen.addAttribute(ele, "minOccurs", "0");
            this.gen.addAttribute(ele, "name", "defaultActionCapabilitySpec");
            this.gen.addAttribute(ele, "type", "DefaultActionCapability");
            seq.appendChild(ele);
        }
        this.gen.addNewElement(elem);

        Element attr = this.gen.newElement("attribute");
        this.gen.addAttribute(attr, "name", "nsfName");
        this.gen.addAttribute(attr, "type", "xs:string");
        elem.appendChild(attr);

        
        /**
         * si ottengono gli attributi possibili nei nodi policy
         * e si aggiungono come possibili attributi di tale nodo
         */
        List<String> policyAttributes = getEnumerationLiterals("PolicyAttributeEnumeration");
        for(String s : policyAttributes) {
            attr = this.gen.newElement("attribute");
            this.gen.addAttribute(attr, "name", s);
            this.gen.addAttribute(attr, "type", "xs:string");
            elem.appendChild(attr);

        }

        //for specifico per creare il linguaggio solo con le securityCapability per la nsf specifica
        for (int i = 0; i < securityCapabilityList.getLength(); i++) {
            baseNewSecCap = nameSecurityCapability((Element) securityCapabilityList.item(i));
            if (baseNewSecCap != null) {
                // System.out.println(baseNewSecCap);
                nameNewSecCap = idSecurityCapability((Element) securityCapabilityList.item(i));
                //System.out.println(nameNewSecCap[k]);
                for (int j = 0; j < refSecCapList.getLength(); j++) {
                    if (!(refSecCapList.item(j) instanceof DeferredElementImpl)) { //fattibile solo includendo la libreria relativa 
                        continue;
                    }
                    String nodeName = refSecCapList.item(j).getNodeName();
                    if(nodeName.equals("securityCapability")) {
                        String refSecCap = refSecurityCapability((Element) refSecCapList.item(j));
                        // System.out.println(refSecCap);
                        if (refSecCap.equalsIgnoreCase(nameNewSecCap)) {
                            elem = this.gen.newElement("complexType");
                            this.gen.addAttribute(elem, "name", nameNewSecCap);

                            Element content = this.gen.newElement("complexContent");
                            elem.appendChild(content);

                            Element extension = this.gen.newElement("extension");
                            this.gen.addAttribute(extension, "base", baseNewSecCap);
                            content.appendChild(extension);

                            this.gen.addNewElement(elem);
                            baseNewSecCapList[index] = baseNewSecCap;
                            nameNewSecCapList[index] = nameNewSecCap;
                            index++;
                        }
                    }
                }
            }
        }
        int lenghtOfSecCap = index;
        //System.out.println(lenghtOfSecCap);

        // //genero il nuovo complex type DefaultActionCapability 
        // elem = this.gen.newElement("complexType");
        // this.gen.addAttribute(elem, "name", "DefaultActionCapability");
        // Element choice = this.gen.newElement("choice");
        // this.gen.addAttribute(choice, "maxOccurs", "unbounded");
        // elem.appendChild(choice);

        // for (int i = 0; i < lenghtOfSecCap; i++) {
        //     ele = this.gen.newElement("element");
        //     String lowerCase = nameNewSecCapList[i].substring(0, 1).toLowerCase() + nameNewSecCapList[i].substring(1);
        //     if(lowerCase.contains("defaultActionCapabilitySpec"))
        //         continue;
        //     this.gen.addAttribute(ele, "name", lowerCase);
        //     this.gen.addAttribute(ele, "type", nameNewSecCapList[i]);
        //     choice.appendChild(ele);
        // }

        // this.gen.addNewElement(elem);


        //genero il nuovo complex type Rule 
        elem = this.gen.newElement("complexType");
        this.gen.addAttribute(elem, "name", "Rule");
        Element choice = this.gen.newElement("choice");
        this.gen.addAttribute(choice, "maxOccurs", "unbounded");
        elem.appendChild(choice);
        ele = this.gen.newElement("element");
        this.gen.addAttribute(ele, "name", "ruleDescription");
        this.gen.addAttribute(ele, "type", "xs:string");
        choice.appendChild(ele);
        ele = this.gen.newElement("element");
        this.gen.addAttribute(ele, "name", "label");
        this.gen.addAttribute(ele, "type", "xs:string");
        choice.appendChild(ele);
        // element node to make possible to add externalData node in RuleInstance.xml
        ele = this.gen.newElement("element");
        this.gen.addAttribute(ele, "name", "externalData");
        this.gen.addAttribute(ele, "type", "ExternalData");
        choice.appendChild(ele);

        for (int i = 0; i < lenghtOfSecCap; i++) {
            ele = this.gen.newElement("element");
            String lowerCase = nameNewSecCapList[i].substring(0, 1).toLowerCase() + nameNewSecCapList[i].substring(1);
            this.gen.addAttribute(ele, "name", lowerCase);
            this.gen.addAttribute(ele, "type", nameNewSecCapList[i]);
            choice.appendChild(ele);
        }

        attr = this.gen.newElement("attribute");
        this.gen.addAttribute(attr, "name", "id");
        this.gen.addAttribute(attr, "type", "xs:string");
        elem.appendChild(attr);

        List<String> ruleAttributes = getEnumerationLiterals("RuleAttributeEnumeration");
        for(String s : ruleAttributes) {
            attr = this.gen.newElement("attribute");
            this.gen.addAttribute(attr, "name", s);
            this.gen.addAttribute(attr, "type", "xs:string");
            elem.appendChild(attr);

        }

        this.gen.addNewElement(elem);

        // Si genera il complexType ExternalData che permette di specificare dati esterni per ogni regola
        elem = this.gen.newElement("complexType");
        this.gen.addAttribute(elem, "name", "ExternalData");

        Element content = this.gen.newElement("simpleContent");

        Element extensionElem = this.gen.newElement("extension");
        this.gen.addAttribute(extensionElem, "base", "xs:string");
        
        attr = this.gen.newElement("attribute");
        this.gen.addAttribute(attr, "name", "type");
        this.gen.addAttribute(attr, "type", "xs:string");

        extensionElem.appendChild(attr);

        content.appendChild(extensionElem);

        elem.appendChild(content);

        this.gen.addNewElement(elem);


        //ciclo sulle capability prese dal file xml di input 
        for (int i = 0; i < baseNewSecCapList.length; i++) { 
            //ogni capability viene trasformata in un element
            //String capa = nameSecurityCapability((Element) securityCapabilityList.item(i));	
            String capa = baseNewSecCapList[i];
            //System.out.println(prefix + " \t " + capa);
            
            //NodeList translatorList = securityCapabilityItem.getElementsByTagName("languageGeneratorConstraint");
            /* non servono questi cicli perch� il get element restituisce sicuramente un DeferredElementImpl e c'� una sola istanza sia di translator sia di enumerationName
	    	for(int j = 0; j < trasnlatorList.getLength(); j++) {											//ciclo per generare la mappa dei translator
	    		if(!(trasnlatorList.item(j) instanceof DeferredElementImpl)) { 								//fattibile solo includendo la libreria relativa 
					continue;
				}
	    		Element translator = (Element) trasnlatorList.item(j); 										//elemento che contiene il translator della capability
	    		
	    		NodeList enumerationNameNodeList = translator.getElementsByTagName("enumerationName");
	    		String name = null;
	    		for(int k = 0; k<enumerationNameNodeList.getLength(); k++) {
	    			if(!(enumerationNameNodeList.item(k) instanceof DeferredElementImpl)) { 				//fattibile solo includendo la libreria relativa 
						continue;
					}
	    			Element enumerationNameElement = (Element) enumerationNameNodeList.item(k);
	    			name = enumerationNameElement.getTextContent();											//nome della enumeration, serve per riconoscere l'enumeration stessa ma anche per distinguere i casi protocol e port
	    		}
	    		if(name!=null) {
	    			//System.out.println(name);
	    			translatorConstraintsMap.put(name, translator.getElementsByTagName("value"));
	    		}
	    	}
	    	*/

            /*Element translator = (Element) translatorList.item(0);						//prendo il translator
            if(translator!=null) {
            	translatorConstraintsList.add(translator);								//lo metto nella lista di translator; dentro al translator ci DEVONO essere tutte le informazioni utili
            }*/

            for (NodeList n: complexTypeNodeLists) { //ciclo su tutti i nodelist di tutti i file collegati all'xsd
                found = findOriginalComplexType(n, capa); //cerco il complextype in quella nodelist
                if (found != null) { //se trovo l'elemento agisco su di esso altrimenti ricomincio a cercare con la prossima n
                    findParent(found); //cerco i parenti di questo elemento
                    
                    this.gen.addElement(found); // aggiungo l'elemento
                    break;
                }
            }
        }

        /**
         * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
         * Accenno di funzione che ordina i complexType in base a se fanno riferimento
         * ad altri complexType. È stato osservato come l'ordine con cui i complexType
         * sono
         * esportati da modelio, influisce sulla generazione dei complexTypes nel
         * linguaggio.
         * Se un complexType A ha un elemento di tipo complexType B è necessario che il
         * complexType B
         * sia successivo (in capability_data_model.xsd) al complexType A
         * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
         */
        // List<Element> notSortedNodeList = new ArrayList<>();
        // for (NodeList n: complexTypeNodeLists) {
        // for (int i = 0; i < n.getLength(); i++) {
        // Element typeItem = (Element) n.item(i);
        // notSortedNodeList.add(typeItem);
        // }

        // }
        // Comparator<Element> comparator = new Comparator<Element>() {
        //     @Override
        //     public int compare(Element firstElement, Element secondElement) {
        //         Boolean firstAtLeasOneComplex = false; 
        //         Boolean secondtAtLeasOneComplex = false; 

        //         NodeList firstNl = firstElement.getChildNodes();
        //         for (int i = 0; i < firstNl.getLength(); i++) {
        //             if (!(firstNl.item(i) instanceof DeferredElementImpl)) { //fattibile solo includendo la libreria relativa 
        //                 continue;
        //             }
        //             Element ne = (Element) firstNl.item(i);
        //             if(!ne.getAttribute("type").startsWith("xs:"))
        //                 firstAtLeasOneComplex = true; 
        //         }

        //         NodeList secondtNl = secondElement.getChildNodes();
        //         for (int i = 0; i < secondtNl.getLength(); i++) {
        //             if (!(secondtNl.item(i) instanceof DeferredElementImpl)) { //fattibile solo includendo la libreria relativa 
        //                 continue;
        //             }
        //             Element ne = (Element) secondtNl.item(i);
        //             if(!ne.getAttribute("type").startsWith("xs:"))
        //                 secondtAtLeasOneComplex = true; 
        //         }

        //         if(firstAtLeasOneComplex == secondtAtLeasOneComplex == true | firstAtLeasOneComplex == secondtAtLeasOneComplex == false) {
        //             return 0; 
        //         } else if (firstAtLeasOneComplex == true && secondtAtLeasOneComplex == false) {
        //             return -1; 
        //         } else if (firstAtLeasOneComplex == false && secondtAtLeasOneComplex == true) {
        //             return 1;
        //         }
        //         return 0; 

        //     }
        // };

        // Collections.sort(notSortedNodeList, comparator);

        //genero i tipi complessi
        for (NodeList n: complexTypeNodeLists) {
            this.gen.generateType(n);
        }


        Element defActElement = this.gen.getExistingComplexType("DefaultActionCapability");
        if(defActElement!=null) {
            // genero il nuovo complex type DefaultActionCapability
            Element extElement = (Element)((Element) defActElement.getFirstChild()).getFirstChild(); 
            
            Element choiceFound = this.gen.newElement("choice");
            
            this.gen.addAttribute(choiceFound, "maxOccurs", "unbounded");
            extElement.appendChild(choiceFound);

            for (int j = 0; j < lenghtOfSecCap; j++) {
                ele = this.gen.newElement("element");
                String lowerCase = nameNewSecCapList[j].substring(0, 1).toLowerCase()
                        + nameNewSecCapList[j].substring(1);
                if (lowerCase.contains("defaultActionCapabilitySpec"))
                    continue;
                this.gen.addAttribute(ele, "name", lowerCase);
                this.gen.addAttribute(ele, "type", nameNewSecCapList[j]);
                choiceFound.appendChild(ele);
            }
            extElement.appendChild(choiceFound);
        }

        for (int i = 0; i < languageGenerationList.getLength(); i++) {
            Element translator = (Element) languageGenerationList.item(i); //prendo il translator
            if (translator != null) {
                translatorConstraintsList.add(translator); //lo metto nella lista di translator; dentro al translator ci DEVONO essere tutte le informazioni utili
            }
        }

        //ciclo che generara tutti i tipi che ho nella lista quindi dei quali avevo il translator
        for (Element e: translatorConstraintsList) { //ciclo sui translator
            for (NodeList n: simpleTypeNodeLists) { //ciclo sulle liste di simpletype per ogni import (n contiene una lista di simple type)
                if (generateCustomType(e, n)) { //ogni volta che ricevo false riprovo con un altro simpleTypeNodeList, se ricevo true allora ho generato l'enumeration
                    break;
                }
            }
        }

        //genero i tipi semplici che non sono stati generati dal ciclo sopra, quindi che non avevano il translator
        for (NodeList n: simpleTypeNodeLists) {
            this.gen.generateType(n);
        }

        return this.gen.transform(this.outputName); //final comand to generate the xsd 

    }

    //Funzione per ricevere il nome della security Capability riferita
    private String nameSecurityCapability(Element item) {
        if (!item.getAttribute("id").equalsIgnoreCase("")) {
            String nomeCompleto = item.getAttribute("xsi:type");
            if (nomeCompleto.contains(":")) {
                String[] nome = nomeCompleto.split(":");
                return nome[1]; //contiene il nome dell'elemento interessato (la security capability che devo cerdare)
            } else {
                return nomeCompleto;
            }
        }
        return null;
    }
    //Funzione per ricevere l'id della security Capability riferita
    private String idSecurityCapability(Element item) {
        if (!item.getAttribute("id").equalsIgnoreCase("")) {
            return item.getAttribute("id");
        }
        return null;
    }

    //Funzione per ricevere il ref della security Capability riferita
    private String refSecurityCapability(Element item) {
        if (!item.getAttribute("ref").equalsIgnoreCase("")) {
            return item.getAttribute("ref");
        }
        return null;
    }

    //questa fuzione genera il tipo personalizzato
    private boolean generateCustomType(Element element, NodeList n) {
        NodeList newEnumerationNodeList = element.getElementsByTagName("newEnumeration"); //prendo l'lemento (� unico) new enumeration
        NodeList modifyDefaultNodeList = element.getElementsByTagName("modifyDefault"); //prendo l'elemento modifyDefaultEnumeration
        NodeList enumerationNameNodeList = element.getElementsByTagName("enumerationName"); //prende il nome dell'enumerazione se presente

        String enumerationName = null;
        if (enumerationNameNodeList.getLength() > 0) {
            enumerationName = enumerationNameNodeList.item(0).getTextContent(); //prendo il nome dell'enumerazione in fomrato stringa se esiste
        }

        //System.out.println(enumerationName);

        if (newEnumerationNodeList.getLength() > 0 && modifyDefaultNodeList.getLength() > 0) { //controllo se sono stati inseriti sia una nuova enumerazione sia la modifica dell'esistente
            System.out.println("both newEnumeration and modifyDefaultEnumeration cannot be defined, in element " + enumerationName); //in caso esco perch� non c'� un modo per gestirle (per aggiungere un valore ad una enumeration esistente va utilizzato "addNewValue")
            return false;
        }

        if (newEnumerationNodeList.getLength() > 0) { //controllo se esiste la newEnumeration
            return generateNewStringEnumeration(enumerationName, ((Element) newEnumerationNodeList.item(0)).getElementsByTagName("newValue"));
        }

        if (modifyDefaultNodeList.getLength() > 0) { //controllo se esiste la customizedEnuemration
            return generateCustomizedEnumeration(enumerationName, (Element) modifyDefaultNodeList.item(0), n);
        }

        return false;
    }

    //questa funzione genera l'enumerate con i valori che sono stati specificati nel translator CONTROLLANDO che ci siano anche nell'enumerazione di default
    public boolean generateCustomizedEnumeration(String enumerationName, Element modifyDefaultEnumeration, NodeList modeledNL) {

        NodeList addNewValueNodeList = modifyDefaultEnumeration.getElementsByTagName("addNewValue");
        NodeList renameValueNodeList = modifyDefaultEnumeration.getElementsByTagName("renameValue");
        NodeList removeValueNodeList = modifyDefaultEnumeration.getElementsByTagName("removeValue");
        NodeList addExistingValueNodeList = modifyDefaultEnumeration.getElementsByTagName("addExistingValue");
        NodeList setNumericRangeNodeList = modifyDefaultEnumeration.getElementsByTagName("setNumericRange");
        NodeList generateIntegerMatching = modifyDefaultEnumeration.getElementsByTagName("generateIntegerMatching"); //elemento singolo
        NodeList typeName = modifyDefaultEnumeration.getElementsByTagName("complexTypeWithIntegerAttributeName"); //elemento singolo
        NodeList integerAttributeToBeRestricted = modifyDefaultEnumeration.getElementsByTagName("integerAttributeToBeRestricted");

        Element defaultEnumeration = null;

        List < String > capabilityAndAttributesToBeChanged = new ArrayList < String > (); //in posizione 0 va il complexType da modificare, dalla posizione 1 in poi vanno gli attributi a cui va modificato il tipo

        String metadata;

        if (removeValueNodeList.getLength() > 0 && addExistingValueNodeList.getLength() > 0) { //se esistono entrambi non so gestirlo perch� potrebbe non essere sensato.
            System.out.println("both removeValue and addExistingValue cannot be defined");
            return false;
        }

        if (typeName.getLength() > 0) { //lo faccio a prescindere e controllo dopo, solo quando mi servono se ci sono o no
            capabilityAndAttributesToBeChanged.add(((Element) typeName.item(0)).getTextContent());
        }

        for (int i = 0; i < integerAttributeToBeRestricted.getLength(); i++) { //lo faccio a prescindere e controllo dopo, solo quando mi servono se ci sono o no
            capabilityAndAttributesToBeChanged.add(((Element) integerAttributeToBeRestricted.item(i)).getTextContent());

        }

        if (enumerationName != null) {
            defaultEnumeration = getDefaultEnumeration(enumerationName, modeledNL); //se ho da modificare una enumeration devo cercare quella di default
            if (defaultEnumeration == null) {
                return false;
            }
        } else {
            //caso di rinumerazione intera di un singolo attributo, l'enumerationName non esiste e quindi neanche la modifyDefaultEnumeration
            //in questo caso, non avendo una enumerazione, vuol dire che va modificato solo un tipo di un attributo e creata la relativa enumerazione
            this.gen.newIntegerRestrictedSimpleType(setNumericRangeNodeList, capabilityAndAttributesToBeChanged);
            return true;
        }

        if (enumerationName.contentEquals("ProtocolTypeEnumeration")) { //gestisco la situaizone del protocol type

            metadata = "metadati/number_name_protocols.txt"; //metadati globali, del languageModel

            return createEnumerationWithIntegerMapping(enumerationName, addNewValueNodeList, renameValueNodeList, removeValueNodeList,
                addExistingValueNodeList, defaultEnumeration, setNumericRangeNodeList, generateIntegerMatching, metadata, capabilityAndAttributesToBeChanged);

        } else if (enumerationName.contentEquals("ServicePortNameEnumeration")) { //gestisco la situaizone del del port type

            metadata = "metadati/number_name_ports.txt"; //metadati globali, del languageModel

            return createEnumerationWithIntegerMapping(enumerationName, addNewValueNodeList, renameValueNodeList, removeValueNodeList,
                addExistingValueNodeList, defaultEnumeration, setNumericRangeNodeList, generateIntegerMatching, metadata, capabilityAndAttributesToBeChanged);
        } else { //gestisco le altre enumeration comunicando che la parte intera non verr� considerata
            if (setNumericRangeNodeList.getLength() > 0) {
                System.out.println("no integer capability");
            }
            return createEnumerationNonIntegerMapping(enumerationName, addNewValueNodeList, renameValueNodeList, removeValueNodeList, addExistingValueNodeList, defaultEnumeration);
        }
    }

    //crea l'enumerazione, il tipo intero e modifica il tipo dell'attributo interessato (se presente)
    private boolean createEnumerationWithIntegerMapping(String enumerationName, NodeList addNewValueNodeList,
        NodeList renameValueNodeList, NodeList removeValueNodeList, NodeList addExistingValueNodeList,
        Element defaultEnumeration, NodeList setNumericRangeNodeList, NodeList generateIntegerMatching,
        String metadata, List < String > capabilityAndAttributesToBeChanged) {

        List < String > valuesToBeInserted = new ArrayList < String > ();
        List < String > defaultEnumerationValuesStringList = new ArrayList < String > ();
        NodeList defaultValuesInEnumerationNodeList = defaultEnumeration.getElementsByTagName("xs:enumeration"); //prendo le xs:enumeration dell'enumeration
        Map < String, Integer > nameValueMap = new HashMap < String, Integer > ();
        Map < String, Integer > nameValueDefaultMap = getDefaultMap(metadata);
        if (nameValueDefaultMap == null || nameValueDefaultMap.size() == 0) {
            return false;
        }

        for (int i = 0; i < defaultValuesInEnumerationNodeList.getLength(); i++) {
            defaultEnumerationValuesStringList.add(((Element) defaultValuesInEnumerationNodeList.item(i)).getAttribute("value")); //inserisco i value dell'enumeration nella lista
        }

        if (removeValueNodeList.getLength() > 0) {
            for (int i = 0; i < removeValueNodeList.getLength(); i++) {
                //System.out.println(removeValueNodeList.item(i).getTextContent());
                defaultEnumerationValuesStringList.remove(removeValueNodeList.item(i).getTextContent()); //questo rimuove dalla lista i valori che non sono desiderati
            }
            valuesToBeInserted.addAll(defaultEnumerationValuesStringList); //inserisco tutti i valori rimanenti nella lista finale
        } else if (addExistingValueNodeList.getLength() > 0) {
            for (int i = 0; i < addExistingValueNodeList.getLength(); i++) {
                if (defaultEnumerationValuesStringList.contains(addExistingValueNodeList.item(i).getTextContent())) { //se ho trovato l'elemento allora lo inserisco nella lista degli elementi da inserire
                    valuesToBeInserted.add(addExistingValueNodeList.item(i).getTextContent());
                }
            }
        }

        for (int i = 0; i < valuesToBeInserted.size(); i++) {
            nameValueMap.put(valuesToBeInserted.get(i), nameValueDefaultMap.get(valuesToBeInserted.get(i))); //inserisco i valori rimasti o i valori scelti nella mappa col corrispettivo valore numerico
        }

        if (addNewValueNodeList.getLength() > 0) {
            for (int i = 0; i < addNewValueNodeList.getLength(); i++) {
                valuesToBeInserted.add(((Element)((Element) addNewValueNodeList.item(i)).getElementsByTagName("newValue").item(0)).getTextContent()); //aggiungo l'elemento newValue
                nameValueMap.put(((Element)((Element) addNewValueNodeList.item(i)).getElementsByTagName("newValue").item(0)).getTextContent(), //aggiungo la stringa
                    Integer.valueOf(((Element)((Element) addNewValueNodeList.item(i)).getElementsByTagName("integerMatching").item(0)).getTextContent())); //e il valore numerico corrispondente nella mappa
            }
        }

        if (renameValueNodeList.getLength() > 0) {
            for (int i = 0; i < renameValueNodeList.getLength(); i++) {
                //System.out.println(((Element) renameValueNodeList.item(i)).getElementsByTagName("realName").item(0).getTextContent());
                if (defaultEnumerationValuesStringList.contains(((Element) renameValueNodeList.item(i)).getElementsByTagName("realName").item(0).getTextContent())) { //se esiste il realName
                    valuesToBeInserted.add(((Element) renameValueNodeList.item(i)).getElementsByTagName("myName").item(0).getTextContent()); //aggiungo il myname
                    //System.out.println(((Element) renameValueNodeList.item(i)).getElementsByTagName("myName").item(0).getTextContent() + " "+
                    //		nameValueDefaultMap.get(((Element) renameValueNodeList.item(i)).getElementsByTagName("realName").item(0).getTextContent()));
                    nameValueMap.put(((Element) renameValueNodeList.item(i)).getElementsByTagName("myName").item(0).getTextContent(), //aggiunge come chiave il nuovo nome
                        nameValueDefaultMap.get(((Element) renameValueNodeList.item(i)).getElementsByTagName("realName").item(0).getTextContent())); //e come valore il valore del vero nome
                }
            }
        }

        //System.out.println(addExistingValueNodeList.getLength()+" "+removeValueNodeList.getLength()+" "+addNewValueNodeList.getLength()+" "+renameValueNodeList.getLength()+" "+nameValueMap.size());

        generateMyMetadata(nameValueMap, metadata); //genero il file di metadati
        this.gen.addEnumerationFromList(enumerationName, valuesToBeInserted); //genero l'enumeration

        if (setNumericRangeNodeList.getLength() > 0) { //se esiste il range numerico allora lo agiungo
            this.gen.addNewSimpleTypeIntegerRestrictionFromNodeList(capabilityAndAttributesToBeChanged, setNumericRangeNodeList);
        } else if (generateIntegerMatching.getLength() > 0 && ((Element) generateIntegerMatching.item(0)).getTextContent().contentEquals("true")) { //se integer matching � a true allora genero la restrizione intera
            this.gen.generateIntegerMatchingFromMatchingNumbers(capabilityAndAttributesToBeChanged, sortByValue(nameValueMap));
        }

        return true;
    }

    //genera un file di metadati che rappresenta il matching tra intero e stringa
    private void generateMyMetadata(Map < String, Integer > nameValueMap, String metadata) {

        PrintWriter printer;
        try {
            String[] s = metadata.split("/");
            String outputName = "";
            /*
            for(int i = 0; i < s.length; i++) {								//in questo modo metto il metadato nella cartella metadati standard
            	if(i==s.length-1) {
            		s[i] = "my_"+s[i];
            	}
            	outputName = outputName.concat(s[i]+"/");
            }
            outputName = outputName.substring(0, outputName.length() - 1);   // rimuove l'ultimo carattere
            */
            outputName = "metadati/metadata_" + s[s.length - 1];

            this.metadataPath.add(outputName);

            printer = new PrintWriter(new FileWriter(outputName));

            nameValueMap = sortByValue(nameValueMap);

            for (String key: nameValueMap.keySet()) {
                //System.out.println(nameValueMap.get(key)+"\t"+key);
                printer.append(nameValueMap.get(key) + "\t" + key + "\n");
            }

            printer.flush();
            printer.close();

        } catch (IOException e1) {
            System.out.println("Error: " + e1.getMessage());
            return;
        }

    }

    //funzione che ordina la mappa in funzione del valore intero
    private static Map < String, Integer > sortByValue(Map < String, Integer > unsortMap) {

        List < Map.Entry < String, Integer >> list = new LinkedList < Map.Entry < String, Integer >> (unsortMap.entrySet());

        Collections.sort(list, new Comparator < Map.Entry < String, Integer >> () {
            public int compare(Map.Entry < String, Integer > o1,
                Map.Entry < String, Integer > o2) {
                return (o1.getValue()).compareTo(o2.getValue());
            }
        });

        Map < String, Integer > sortedMap = new LinkedHashMap < String, Integer > ();
        for (Map.Entry < String, Integer > entry: list) {
            sortedMap.put(entry.getKey(), entry.getValue());
        }

        return sortedMap;
    }

    //funzione che cerca e ritorna la mappa di default (presa dal file metadato!)
    private Map < String, Integer > getDefaultMap(String metadata) {
        // deve leggere tutto il file e generare una mappa con chiave il nome del protocollo/porta e come valore il numero
        Map < String, Integer > defaultMap = new HashMap < String, Integer > ();

        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(metadata));
            String rule;
            while ((rule = reader.readLine()) != null) {
                //System.out.println(rule);
                String[] s = rule.split("\t");
                //System.out.println(s[1]+" "+s[0]);
                defaultMap.put(s[1], Integer.valueOf(s[0]));
            }

            reader.close();
            return defaultMap;
        } catch (FileNotFoundException e) {
            System.out.println("Warning: " + e.getMessage() + ". The enumeration is generated with the default values.");
            return null;
        } catch (IOException e) {
            System.out.println("Warning: " + e.getMessage() + ". The enumeration is generated with the default values.");
            return null;
        }
    }

    //funzione che genera il tipo enumeration "semplice" quindi non nel caso di protocol o port
    public boolean createEnumerationNonIntegerMapping(String name, NodeList addNewValueNodeList, NodeList renameValueNodeList,
        NodeList removeValueNodeList, NodeList addExistingValueNodeList, Element defaultEnumeration) {
        List < String > valuesToBeInserted = new ArrayList < String > ();
        List < String > defaultEnumerationValuesStringList = new ArrayList < String > (); //lista con le stringe dell'enumerazione
        NodeList defaultValuesInEnumerationNodeList = defaultEnumeration.getElementsByTagName("xs:enumeration"); //prendo le xs:enumeration dell'enumeration
        //System.out.println("dimensione: "+defaultValues.getLength());
        for (int i = 0; i < defaultValuesInEnumerationNodeList.getLength(); i++) {
            defaultEnumerationValuesStringList.add(((Element) defaultValuesInEnumerationNodeList.item(i)).getAttribute("value")); //inserisco i value dell'enumeration nella lista
        }

        if (removeValueNodeList.getLength() > 0) {
            for (int i = 0; i < removeValueNodeList.getLength(); i++) {
                //System.out.println(removeValueNodeList.item(i).getTextContent());
                defaultEnumerationValuesStringList.remove(removeValueNodeList.item(i).getTextContent()); //questo rimuove dalla lista i valori che non sono desiderati
            }
            valuesToBeInserted.addAll(defaultEnumerationValuesStringList); //inserisco tutti i valori rimanenti nella lista finale
        } else if (addExistingValueNodeList.getLength() > 0) {
            for (int i = 0; i < addExistingValueNodeList.getLength(); i++) {
                if (defaultEnumerationValuesStringList.contains(addExistingValueNodeList.item(i).getTextContent())) { //se ho trovato l'elemento allora lo inserisco nella lista degli elementi da inserire
                    valuesToBeInserted.add(addExistingValueNodeList.item(i).getTextContent());
                }
            }
        }

        if (addNewValueNodeList.getLength() > 0) {
            for (int i = 0; i < addNewValueNodeList.getLength(); i++) {
                valuesToBeInserted.add(((Element)((Element) addNewValueNodeList.item(i)).getElementsByTagName("newValue").item(0)).getTextContent()); //aggiungo l'elemento newValue
            }
        }

        if (renameValueNodeList.getLength() > 0) {
            for (int i = 0; i < renameValueNodeList.getLength(); i++) {
                //System.out.println(((Element) renameValueNodeList.item(i)).getElementsByTagName("realName").item(0).getTextContent());
                if (defaultEnumerationValuesStringList.contains(((Element) renameValueNodeList.item(i)).getElementsByTagName("realName").item(0).getTextContent())) { //se esiste il realName
                    valuesToBeInserted.add(((Element) renameValueNodeList.item(i)).getElementsByTagName("myName").item(0).getTextContent()); //aggiungo il myname
                }
            }
        }

        this.gen.addEnumerationFromList(name, valuesToBeInserted);

        return false;
    }

    //funzione che cerca e restituisce i valori di default dell'enumeration
    private Element getDefaultEnumeration(String name, NodeList modeledNL) {
        boolean found = false;
        Element enumerateFound = null;
        for (int i = 0; i < modeledNL.getLength(); i++) {
            if (!(modeledNL.item(i) instanceof DeferredElementImpl)) { //fattibile solo includendo la libreria relativa 
                continue;
            }
            Element enumerate = (Element) modeledNL.item(i);
            //System.out.println(enumerate.getAttribute("name"));
            if (enumerate.getAttribute("name").compareToIgnoreCase(name) == 0) {
                //System.out.println("trovato "+name);
                enumerateFound = enumerate;
                found = true;
                break;
            }
        }
        if (!found)
            return null;
        return enumerateFound;
    }

    //genera l'enumerate senza controllare l'esistenza dei parametri
    public boolean generateNewStringEnumeration(String name, NodeList valueNL) {

        if (this.gen.capabilityInListYet(name)) {
            return false;
        }
        this.gen.addCapaInList(name);
        Element customEnumeration = this.gen.newElement("simpleType");
        this.gen.addAttribute(customEnumeration, "name", name);
        Element restriction = this.gen.newElement("restriction");
        this.gen.addAttribute(restriction, "base", "xs:string");

        for (int i = 0; i < valueNL.getLength(); i++) {
            if (!(valueNL.item(i) instanceof DeferredElementImpl)) { //fattibile solo includendo la libreria relativa 
                continue;
            }
            Element value = (Element) valueNL.item(i);
            Element enumValue = this.gen.newElement("enumeration");
            this.gen.addAttribute(enumValue, "value", value.getTextContent());
            restriction.appendChild(enumValue);
        }
        customEnumeration.appendChild(restriction);
        this.gen.addNewElement(customEnumeration);

        return true;
    }

    //funzione che data ua lista di nodi contenenti i complextype (del file generale) e data una capability (presa dall'istanza xml) ritorna l'elemento generale oppure null
    private static Element findOriginalComplexType(NodeList complextype, String capa) {
        for (int j = 0; j < complextype.getLength(); j++) {
            Element complex = (Element) complextype.item(j);
            if (complex.getAttribute("name").equalsIgnoreCase(capa)) {
                return complex;
            }
        }
        return null;
    }

    //funzione che cerca gli elementi che sono "genitori" rispetto all'elemento di partenza in modo ricorsivo e chiama la funzione per aggiungere ogni elemento al nodo per generare il nuovo xsd
    private Element findParent(Element complextype) {
        //XSDgenerator gen = XSDgenerator.getGenerator();							//prendo il singleton

        Element parent = findExtensionElement(complextype); //trovo l'elemento che mi dice il parente  <xs:extension base="baseCapability:SecurityCapability"/>

        String[] nome = parent.getAttribute("base").split(":");
        String capa;
        if (nome.length > 1) {
            capa = nome[1];
        } else {
            capa = nome[0];
        }

        if (capa.equalsIgnoreCase("NSFCatalogue") || capa.equalsIgnoreCase("NSF") || capa.equalsIgnoreCase("HasSecurityCapabilityDetails") || capa.equalsIgnoreCase("HasSecurityCapabilityDetails")) { //confronto con gli elementi piu "generali" quindi che non ereditano da nessuno

            if (!this.gen.capabilityInListYet(capa)) {
                //ci entro solo una volta, la pirma volta che trovo SecurityCapability
                //modifico il complex type di SecurityCapability per far si che abbia come riferimento rule e non root
                //volendo si pu� proprio eliminare l'elemento che si riferisce a qualcosa di "superiore"

                for (NodeList n: this.complexTypeNodeLists) { //cerco in tutti i nodeList dell'xsd
                    Element element = findOriginalComplexType(n, capa); //il complexType relativo alla capability che � padre dell'elemento che sto considerando
                    if (element != null) { //trovo la capability con quel nome
                        //System.out.println(element.getAttribute("name"));
                        NodeList node = element.getChildNodes();
                        Element seq = null;
                        Element e = null;
                        for (int i = 0; i < node.getLength(); i++) {
                            if (!(node.item(i) instanceof DeferredElementImpl)) { //fattibile solo includendo la libreria relativa 
                                continue;
                            }
                            seq = (Element) node.item(i);

                            if (seq.getTagName().equalsIgnoreCase("xs:sequence")) {
                                break;
                            }
                        }
                        if (seq != null) {
                            node = seq.getChildNodes();
                            for (int i = 0; i < node.getLength(); i++) {
                                if (!(node.item(i) instanceof DeferredElementImpl)) { //fattibile solo includendo la libreria relativa 
                                    continue;
                                }
                                e = (Element) node.item(i);
                                //System.out.println(e.getTagName());
                                String s = e.getAttribute("type");
                                if (s.contains("Root")) {
                                    e.setAttribute("type", "Rule");
                                    e.setAttribute("name", "rule");
                                }
                            }
                        }

                        this.gen.addElement(element);
                        break;
                    }
                }
            }
            return null;
        } else {
            for (NodeList n: this.complexTypeNodeLists) { //cerco in tutti i nodeList dell'xsd
                Element element = findOriginalComplexType(n, capa); //il complexType relativo alla capability che � padre dell'elemento che sto considerando
                if (element != null) { //trovo la capability con quel nome	
                    findParent(element);
                    this.gen.addElement(element);
                    break;
                }
            }
        }
        return null;
    }

    //cerca se nei vari elementi interni all'elemento passato esiste un elemento "xs:extension" ed in caso ritorna quello 
    private Element findExtensionElement(Element e) {
        String base = e.getAttribute("base"); //l'attributo "base" dovrebbe essere solo in "extension" quindi quando lo trovo ho trovato l'extension
        if (base != "") {
            return e;
        }
        if (!e.hasChildNodes()) {
            return null;
        }
        NodeList nodes = e.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            if (!(nodes.item(i) instanceof DeferredElementImpl)) { //fattibile solo includendo la libreria relativa 
                continue;
            }
            return findExtensionElement((Element) nodes.item(i));
        }
        return null;
    }

    //genera la lista dei nodi da un documento rispetto ad un tagName
    private static NodeList getNodelistOfElementFromDocumentByTagname(Document d, String tagname) {
        return d.getElementsByTagName(tagname);
    }

    //genera il documento in base al path (relativo al progetto o globale se si parte da C://
    private static Document generateDocument(String path) {
        DocumentBuilderFactory df;
        DocumentBuilder builder;
        df = DocumentBuilderFactory.newInstance();

        try {
            builder = df.newDocumentBuilder();
            return builder.parse(path);
        } catch (ParserConfigurationException e) {
            System.out.println("Error: " + e.getMessage());
        } catch (SAXException e) {
            System.out.println("Error: " + e.getMessage());
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
        return null;
    }

    //genera un lista contenente tutti i path degli import
    private List < String > getAllImportPaths() {
        List < String > importList = new ArrayList < String > ();
        Document d = generateDocument(this.xsd);
        if (d == null) {
            System.out.println(this.xsd + " document not found");
            return null;
        }

        NodeList importNode = getNodelistOfElementFromDocumentByTagname(d, "xs:import");
        for (int i = 0; i < importNode.getLength(); i++) {
            Element importTag = (Element) importNode.item(i);
            //importList.add(importTag.getAttribute("schemaLocation"));
            //System.out.println("questo �: "+importTag.getAttribute("schemaLocation"));
            String[] fullName = this.xsd.split("/");
            String s = "";
            for (int j = 0; j < fullName.length - 1; j++) {
                s += fullName[j];
                s += "/";
            }
            s += importTag.getAttribute("schemaLocation");
            //System.out.println("diventa: "+s);
            importList.add(s);
        }
        return importList;
    }

    //genera una lista di nodeList contenente per ogni import la nodelist contenente gli elementi con quel tag
    private List < NodeList > getAllNodelistFromImportsByTagName(List < String > imports, String tag) {
        List < NodeList > nodes = new ArrayList < NodeList > ();
        for (String s: imports) {
            //System.out.println(s);
            Document d = (generateDocument(s));
            if (d == null) {
                System.out.println(s + " document not found");
                return null;
            }
            NodeList n = getNodelistOfElementFromDocumentByTagname(d, tag);
            nodes.add(n);
        }
        return nodes;
    }

    public List < String > getMetadataPathList() {
        return this.metadataPath;
    }

    /**
     * Funzione che restituisce i valori di un enumeration
     */
    private List<String> getEnumerationLiterals(String enumerationName) {
        List<NodeList> allNodeLists = getAllNodelistFromImportsByTagName(this.imports, "xs:simpleType");
        List<String> enumerationStrings = new ArrayList<>();
        
        for(NodeList ns : allNodeLists){
            // ciclo per popolare enumerationStrings
            for (int i = 0; i < ns.getLength(); i++) {
                Element e1 = getElemenetIfDeferredElementImpl(ns.item(i));
                if (e1 == null)
                    continue;
                if (e1.getAttribute("name").equalsIgnoreCase(enumerationName)) {
                    NodeList nl2 = e1.getElementsByTagName("xs:enumeration");
                    // se la capability interessata ha dei child elements
                    if (nl2.getLength() > 0) {
                        for (int j = 0; j < nl2.getLength(); j++) { // per ogni elemento nel complexType
                            Element e2 = getElemenetIfDeferredElementImpl(nl2.item(j));
                            if (e2 == null)
                                continue;
                                enumerationStrings.add(e2.getAttribute("value"));
                        }
                    }
                }
            }
        }        

        return enumerationStrings;
    }
    // funzione che controlla se il nodo � un nodo di tipo elemento, se vero ne
    // ritorna l'Elemento castato altrimenti torna null
    private Element getElemenetIfDeferredElementImpl(Node n) {
        if (n instanceof DeferredElementImpl) {
            // fattibile solo includendo la libreria relativa
            return (Element) n;
        }
        return null;
    }

    private Boolean isSecurityCapabilityInList(NodeList refSecCapList, String capabilityToCheck) {
        Boolean isInList = false; 
        for (int i = 0; i < refSecCapList.getLength(); i++) {
            if(!(refSecCapList.item(i) instanceof DeferredElementImpl))
                continue;
            String securityCapabilityName = refSecurityCapability((Element)refSecCapList.item(i));
            if(securityCapabilityName!=null && securityCapabilityName.equalsIgnoreCase(capabilityToCheck)) {
                isInList = true;
                break; 
            }
        }
        return isInList;
    }

}