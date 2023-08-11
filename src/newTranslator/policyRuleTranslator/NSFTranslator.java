package policyRuleTranslator;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

import javax.lang.model.util.ElementScanner6;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import dk.brics.automaton.*;
import com.mifmif.common.regex.Generex;

import org.apache.xerces.dom.DeferredElementImpl;
import org.apache.xerces.dom.ElementImpl;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import inet.ipaddr.*;
import inet.ipaddr.ipv4.*;
import validatore.Validatore;


public class NSFTranslator {
    // xsd con il linguaggio dell'NSF; xml con le regole da convertire a questo NSF;
    // xml con l'elenco delle capability di questo nsf e quindi gl iadapter; nome
    // del file dove generare l'output
    private String xsdLanguage, xmlRule, xmlCatalogue, outputName;
    // regola temporanea su cui viene riscritta ogni volta la regola (per ogni
    // regola presente in xml)
    private String temporaryRule;
    // stringa che contiene il nome della capability e una "lista" di nome valore
    // per ogni campo
    protected String temporaryCapabilityAndAttributes;
    // stringa che contiene il nome della capability
    protected String temporaryCapability;
    // lista che contiene tutte le capability della regola
    private List<String> temporaryListCapabilityOfRule;
    // elemento per permettere la stampa su file
    private FileWriter fileWriter;
    // elemento per permettere la stampa su file
    private PrintWriter printWriter;
    // elemento che contiene la lista dei nodi securityCapability che contengono le
    // informazioni degli adapter per ogni capability
    private NodeList translationNodes;
    private String nsfName;
    private String nextCapabilityTemp;
    private NodeList nodes;
    private Element nextCapabilityElement;
    // elemento che contiene il translationDetails della capability preso da
    protected Element myCapabilityTranslation;

    // stringa che contiene il nome dell'operatore usato dal parametro
    // della condition capability
    String requestedConditionOperator;
    // della action capability
    String requestedActionOperator;

    // id della regola corrente
    String ruleId;

    // boolean usato nel controllo delle regex per i valori delle capability
    Boolean regexAssumption;

    NodeList allCapas;
    Map<String, String> attributeRegexMap;
    Map<String, String> attributeTransformMap;
    Map<String, List<List<Integer>>> attributeFromToMap;
    static NSFTranslator it;

    // lista di bodyconcatenator di una capability
    List<BodyConcatenator> bodyConcatenators;
    NodeList bodyConcatenatorNL;

    // lista di rule di output
    Map<Integer, String> finalPolicies;

    // string per salvare external data per ogni rule 
    String externalDataValue;

    // map che indica gli attributi nel nodo policy e i rispettivi valori 
    Map<String, String> policyAttributeValues;

    // map che indica gli attributi nel nodo rule e i rispettivi valori 
    Map<String, String> ruleAttributeValues;

    // boolean usato per controllare se una security capability è già presente nella regola 
    // quando si deve aggiungere una default capability 
    Boolean securityCapabilityAlreadyExists;

    String capabilityType; 

    NSFPolicyDetail nsfPolicyDetail;
    
    //Cointatore id ACL per Squid NSF 
    Integer aclCounter = 0, aclRuleCounter = 0; 

    // Stringhe che costituiscono la regola tradotta
    String pre, mid, body, post;

    //Liste di stringhe che contengono i dettagli di quale nome del comando della Security Capability utilizzare 
    // rese globali poiché necessarie a più metodi (modifica effettuata per supporto a attributeCheck in Squid NSF)
    List<String> realCommandName = new ArrayList<String>(),
    commandAttributeNameCondition = new ArrayList<String>(),
    commandAttributeValueCondition = new ArrayList<String>(),
    commandAttributeCheck = new ArrayList<String>();

    // la mia idea � che una NSF pu� avere una istanza di questa classe, e quando ha
    // bisogno diconvertire chiama adatta() passandogli i relativi xsd, xml,
    // fileDiOutput
    public static void main(String[] args){

        /**
         * String languagePathXSD = "language_Strongswan.xsd"; String nsfCatalogue =
         * "NSFCatalogue.xml"; String ruleInstanceXML = "Strongswan_RuleInstance.xml";
         * String outputFile = null; String starter = "conn ";
         */

        String languagePathXSD = null;
        String nsfCatalogue = null;
        String ruleInstanceXML = null;
        String outputFile = null;
        String starter = null;
        String finisher = null;
        String forced = null;
        boolean scr = false;
        boolean ecr = false;
        String destinationNSF = null;
        

        if (args.length < 3 || args.length > 10) {
            System.out.println("bad arguments error");
            return;
        } else {
            languagePathXSD = args[0];
            // System.out.println(languagePathXSD);
            nsfCatalogue = args[1];
            // System.out.println(nsfCatalogue);
            ruleInstanceXML = args[2];
            // System.out.println(ruleInstanceXML);
            for (int i = 3; i < args.length; i++) {
                if (args[i].contains("+s")) {
                    starter = args[i].substring(2);
                    // System.out.println(starter);
                } else if (args[i].contains("+e")) {
                    finisher = args[i].substring(2);
                    // System.out.println("fin = "+finisher);
                } else if (args[i].contentEquals("-f")) {
                    forced = args[i];
                    // System.out.println(forced);
                } else if (args[i].contentEquals("+crs")) {
                    scr = true;
                } else if (args[i].contentEquals("+cre")) {
                    ecr = true;
                } else if (args[i].contains("+toNSF")) { 
                    // nuovo parametro in ingresso usato per la traduzione di regole per NSF generici
                    destinationNSF = args[i].substring(6);                    
                } else if (outputFile == null) {
                    outputFile = args[i];
                    // System.out.println(outputFile);
                } else {
                    System.out.println("bad arguments format");
                    return;
                }
            }
        }
        it = new NSFTranslator();
        it.translate(languagePathXSD, nsfCatalogue, ruleInstanceXML, outputFile, starter, finisher, forced, scr, ecr, destinationNSF);
    }

    public NSFTranslator() {
        this.temporaryListCapabilityOfRule = new ArrayList<String>();
    }

    public boolean validate() {
        Validatore v = new Validatore(this.xsdLanguage, this.xmlRule);
        if (!v.validate()) {
            System.out.println("the instance is invalid");
            return false;
        }
        return true;
    }

    // funzione che riceve 5 parametri,
    // 1) xsd = linguaggio dell'nsf, file xsd al quale fa riferimento il file xml;
    // 2) xmlAdapter = file conl quale � stato generato il linguaggio, � il file
    // creato a mano che contiene le capability interessate e i dettagli per
    // l'adapter
    // 3) xmlRule = file con le regole secondo il linguaggio specificato in xsd;
    // 4) outputName = file su cui fare l'output, nullabile
    // 5) startString = parametro stringa che mi permette di stabilire se voglio una
    // "parte" iniziale della stringa uguale per ogni rule, nullabile

    public void translate(String xsd, String xmlCatalogue, String xmlRule, String outputName, String startString,
            String endString, String forced, boolean scr, boolean ecr, String destinationNSF) {
        this.xsdLanguage = xsd;
        this.xmlCatalogue = xmlCatalogue;
        this.xmlRule = xmlRule;
        this.translationNodes = getNodelistOfElementFromDocumentByTagname(generateDocument(this.xmlCatalogue),
                "capabilityTranslationDetails");
        String myStartString = startString;
        String myEndString = endString;
        boolean force = false;
        this.nextCapabilityTemp = null;
        this.nodes = null;
        this.nextCapabilityElement = null;
        this.finalPolicies = new TreeMap<>();
        this.policyAttributeValues = new HashMap<>();
        this.ruleAttributeValues = new HashMap<>();
        this.capabilityType = null; 

        if (forced != null) {
            force = true;
        }

        // controllo che l'istanza delle regole nell' xml sia una istanza relativa
        // all'xsd del linguaggio
        if (!validate()) {
            return;
        }

        Document xmlRuleDocument = generateDocument(this.xmlRule);
        // prendo tutti i nodi che si chiamano rule
        NodeList ruleList = getNodelistOfElementFromDocumentByTagname(xmlRuleDocument, "rule");
        Element policy = (Element) xmlRuleDocument.getElementsByTagName("policy").item(0);
        if(destinationNSF != null) //se la variabile non è null, allora vuol dire che è stato richiesto una generazione di policy per NSF generici
            this.nsfName = destinationNSF; 
        else 
            this.nsfName = policy.getAttribute("nsfName").toString();

        // si ottiene la lista dei nodi nSF
        NodeList nsfList = getNodelistOfElementFromDocumentByTagname(generateDocument(this.xmlCatalogue),
                "nSF");

        // si ottiene l'NSFPolicyDetails contenente i dettagli di come le rule devono
        // essere formate
        nsfPolicyDetail = getNSFPolicyDetail(nsfList);

        // se la nsf richiede di usare degli attributi nel nodo policy
        if (nsfPolicyDetail != null && nsfPolicyDetail.requiredPolicyAttributes != null) {
            // si ricavano tali attributi dal nodo policy
            for (String s : nsfPolicyDetail.requiredPolicyAttributes) {
                String attributeValue = policy.getAttribute(s).toString();
                if (attributeValue != null && !attributeValue.equals("")) {
                    // key: nome dell'attributo, value: valore dell'attributo
                    policyAttributeValues.put(s, attributeValue);
                } else if(nsfName.equalsIgnoreCase("xfrm")){
                    System.out.println(
                            "ERROR: Missing required policy attribute " + s + " for " + nsfName + " NSF policy.");
                    break;
                }
            }
        }

        // controllo se esiste un nome di output o mettere quello di default
        if (outputName != null) {
            if(outputName.endsWith("/")) {
                if(destinationNSF != null)
                    this.outputName = outputName.concat("policy_" + policy.getAttribute("nsfName").toString() + "to" + destinationNSF + ".txt");
                else
                    this.outputName = outputName.concat("policy_" + this.nsfName + ".txt");
            }
            else 
                this.outputName = outputName;
        } else {
            if(destinationNSF != null)
                this.outputName = "policy_" + policy.getAttribute("nsfName").toString() + "to" + destinationNSF + ".txt";
            else
                this.outputName = "policy_" + this.nsfName + ".txt";
        }
        try {
            // creo un nuovo file se esistente
            File f = new File(this.outputName);
            if(outputName.contains("/")) 
                f.getParentFile().mkdirs();
            this.fileWriter = new FileWriter(f);
            // Set true for append mode
            this.fileWriter = new FileWriter(f, true);
            this.printWriter = new PrintWriter(this.fileWriter);
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }

        /**
         * String[] idSecCap = new String[this.securityNodes.getLength()]; int k=0;
         * for(int i = 0; i<this.securityNodes.getLength(); i++){ idSecCap[k] =
         * idSecurityCapability((Element) this.securityNodes.item(i)); if (idSecCap[k]
         * != null) k++; }
         */

        // System.out.println("nsfName = " + this.nsfName);

        // si ottengono i nodi resolutionStrategyDetails contenenti i dettagli sulle
        // resolutionStrategy note all'NFSTranslator
        NodeList resolutionStrategyNodeList = getNodelistOfElementFromDocumentByTagname(
                generateDocument(this.xmlCatalogue),
                "resolutionStrategyDetails");
        // si ottiene un hashmap con key:nome della resolutionStrategy e
        // value:externalData type richiesto
        Map<String, String> availableResolutionStrategyDetails = findResolutionStrategyDetails(
                resolutionStrategyNodeList);

        // ciclo sulle regole
        for (int i = 0; i < ruleList.getLength(); i++) {

            /**
             * la regola può essere inizializzata con tre valori diversi:
             * - con la stringa ottenuta dall'nsfPolicyDetails, se disponibile
             * - con la stringa passata con +s
             * - stringa vuota se nessuno dei due precedenti
             */
            if (nsfPolicyDetail != null) {
                if (nsfPolicyDetail.ruleStart != null) {
                    this.temporaryRule = nsfPolicyDetail.ruleStart;
                }
            } else if (myStartString != null) {
                this.temporaryRule = myStartString;
            } else {
                this.temporaryRule = "";
            }
            if (scr) {
                this.temporaryRule = this.temporaryRule.concat("\n");
            }

            this.temporaryListCapabilityOfRule = new ArrayList<String>();

            regexAssumption = true;

            Node rule = ruleList.item(i);

            ruleId = ((Element) rule).getAttribute("id");

            if (!(rule instanceof DeferredElementImpl)) { // fattibile solo includendo la libreria relativa
                continue;
            }

            // prima di iniziare a tradurre una regola, si controlla se la NSF richieda di
            // utilizzare una defaultSecurityCapability
            if (nsfPolicyDetail!=null && nsfPolicyDetail.defaultSecurityCapability != null) {
                // in tal caso, si aggiunge un nodo chiamato come defaultSecurityCapability come
                // primo elemento della regola
                this.nodes = rule.getChildNodes();
                // si controlla se un nodo di tipo defaultSecurityCapability già esiste nella
                // regola
                securityCapabilityAlreadyExists = false;
                for (int j = 0; j < nodes.getLength(); j++) { // ciclo sulle capability all'interno della rule
                                                              // selezionata
                    if (!(nodes.item(j) instanceof ElementImpl)) { // fattibile solo includendo la libreria relativa
                        continue;
                    }
                    // converto il nodo della capability in un elemento per poterlo gestire meglio
                    Element capability = (Element) nodes.item(j);

                    if (capability.getNodeName().equals(nsfPolicyDetail.defaultSecurityCapability)) {
                        securityCapabilityAlreadyExists = true;
                    }
                }
                // se non esiste un nodo con lo stesso nome, allora si aggiunge come primo nodo
                // alla regola corrente
                if (!securityCapabilityAlreadyExists) {
                    Element defaultSecurityCapability = xmlRuleDocument
                            .createElement(nsfPolicyDetail.defaultSecurityCapability);
                    rule.insertBefore(defaultSecurityCapability, rule.getChildNodes().item(0));
                    this.temporaryCapability = defaultSecurityCapability.getNodeName();
                }
            }

            // se la nsf richiede di usare degli attributi nel nodo rule
            if (nsfPolicyDetail!=null && nsfPolicyDetail.requiredRuleAttributes != null) {
                // si ricavano tali attributi dal nodo rule
                for (String s : nsfPolicyDetail.requiredRuleAttributes) {
                    String ruleAttributeValue = ((Element) rule).getAttribute(s).toString();
                    if (ruleAttributeValue != null && !ruleAttributeValue.equals("")) {
                        // key: nome dell'attributo, value: valore dell'attributo
                        ruleAttributeValues.put(s, ruleAttributeValue);
                    } else {
                        // System.out.println(
                        //         "ERROR: Missing required rule attribute " + s + " for " + nsfName + " NSF policy.");
                        break;
                    }
                }
            }

            this.nodes = rule.getChildNodes();
            // System.out.println("ciclo sulle security capability " +
            // secCapas.getLength());

            for (int j = 0; j < nodes.getLength(); j++) { // ciclo sulle capability all'interno della rule selezionata
                if (!(nodes.item(j) instanceof ElementImpl)) { // fattibile solo includendo la libreria relativa
                    continue;
                }
                // converto il nodo della capability in un elemento per poterlo gestire meglio
                Element capability = (Element) nodes.item(j);
                // estraggo la capability successiva a quella corrente
                if (j < nodes.getLength() - 1) {
                    if (!(nodes.item(j + 1) instanceof ElementImpl)) { // fattibile solo includendo la libreria
                        // relativa
                        if(nodes.item(j + 2) instanceof ElementImpl)
                            this.nextCapabilityElement = (Element) nodes.item(j + 2);
                    } else
                        this.nextCapabilityElement = (Element) nodes.item(j + 1);
                } else { // la capability corrente è l'ultima capability
                    this.nextCapabilityElement = null;
                }

                if (capability.getNodeName() == "ruleDescription") {
                    // Da definire il comportamento quando questo campo è utilizzato
                    continue;
                }
                if (capability.getNodeName() == "label") {
                    this.temporaryRule = this.temporaryRule.concat(capability.getTextContent() + "\n");
                    continue;
                }

                /**
                 * All'interno delle Rule è possibile fornire dei dati esterni tramite nodi
                 * externalData che possono essere di diverso tipo, ad ora solo il tipo priority
                 * è supportato
                 */
                // se nella regola si forniscono dei dati esterni (nodo externalData)
                if (capability.getNodeName() == "externalData") {
                    // si controlla se la NSF corrente richiede l'uso di una resolutionStrategy
                    if (nsfPolicyDetail.resolutionStrategyInfo != null) {
                        // si controlla che tipo di externalData richiede la resolution strategy
                        // selezionata
                        if (availableResolutionStrategyDetails.containsKey(nsfPolicyDetail.resolutionStrategyInfo)) {
                            String externalDataType = null;
                            String requiredExternalDataType = availableResolutionStrategyDetails
                                    .get(nsfPolicyDetail.resolutionStrategyInfo);

                            // si ricava il type dell'externalData
                            externalDataType = capability.getAttribute("type");
                            // si verifica se il type dell'externalData indicato nella rule coincide con il
                            // type che supporta la resolution strategy
                            if (externalDataType.equals(requiredExternalDataType))
                                externalDataValue = capability.getTextContent();
                            else
                                System.out.println("[Rule #" + ruleId + "]"
                                        + " WARNING: Rule tried to use uknown externalData " + externalDataType
                                        + " for " + nsfPolicyDetail.resolutionStrategyInfo + " Resolution Strategy.");

                            continue;

                        }
                    } else {
                        // nella rule si sta usando un externalData mentre la NSF non richiede alcuna
                        // resolutionStrategy
                        System.out.println("[Rule #" + ruleId + "]"
                                + " WARNING: Rule tried to use externalData while it was not required.");
                        continue;
                    }
                }
                // else {
                // // System.out.println("ERROR: "+nsfName+" requires to use
                // "+nsfPolicyDetail.resolutionStrategyInfo+" Resolution Strategy that
                // NSFTranslator does not support.");
                // continue;
                // }

                List<String> supportedConditionOperator = getEnumerationLiterals("SupportedConditionOperatorEnumeration"); 
                List<String> supportedActionOperator = getEnumerationLiterals("SupportedActionOperatorEnumeration"); 
                // Si ottiene il valore di operator per la security capability in questione
                if (capability.getAttribute("operator") != "") {
                    // si differenzia l'utilizzo dell'operatore in base al tipo della capability
                    if(capability.getNodeName().contains("Condition")) {
                        if(supportedConditionOperator.contains(capability.getAttribute("operator"))) {
                            requestedConditionOperator = capability.getAttribute("operator");
                        } else {
                            System.out.println("[Rule #" + ruleId + "]" + " ERROR: " + capability.getNodeName()
                                        + " tried to use an operator not supported for Condition Capabilities.");
                            this.temporaryRule = ""; 
                            break;
                        }
                    } else if(capability.getNodeName().contains("Action")) {
                        capabilityType = "Action";
                        if(supportedActionOperator.contains(capability.getAttribute("operator"))) {
                            requestedActionOperator = capability.getAttribute("operator");
                        } else {
                            System.out.println("[Rule #" + ruleId + "]" + " ERROR: " + capability.getNodeName()
                                        + " tried to use an operator not supported for Action Capabilities.");
                            this.temporaryRule = ""; 
                            break;
                        }
                    }
                }
                if(capability.getNodeName().contains("Condition"))
                    capabilityType = "Condition";
                else 
                    capabilityType = "Action";


                this.temporaryCapabilityAndAttributes = "";
                // chiamo la funzione che genera la scrittura della regola nello standard deciso
                exploreElement(capability);
                // System.out.println(this.temporaryCapabilityAndAttributes);

                // traduco la clausola chiamando la funzione che si occupa di parlare con il
                // LanguageAdapter

                String ret = clauseConverter(destinationNSF);
                if (ret != null) {
                    // se ho tradotto in qualcosa di utile allora lo aggiungo alla regola
                    this.temporaryRule = this.temporaryRule + ret;
                    this.temporaryListCapabilityOfRule.add(this.temporaryCapability);
                } else {
                    // se clauseConverter ritorna null, allora si assume che c’è stato un
                    // problema durante la traduzione di una regola.
                    // System.out.println("[Rule #"+ruleId+"] Rule is not correct, it will not be
                    // translated.");
                    // Si azzerano le variabili di supporto per la traduzione e si esce dalla
                    // traduzione della regola corrente
                    // A differenza della versione precedente, si continuano a tradurre le regole
                    // successive
                    this.temporaryRule = "";
                    requestedConditionOperator = null;
                    requestedActionOperator = null;
                    j = nodes.getLength();
                    continue;
                }
            }
            
            aclRuleCounter = 0; 

            // si controlla se è necessario post-porre alla regola una stringa indicata
            // nell'NSFCagalogue
            if (nsfPolicyDetail != null && nsfPolicyDetail.ruleEnd != "" && nsfPolicyDetail.ruleEnd != null) {

                this.temporaryRule = this.temporaryRule.concat(nsfPolicyDetail.ruleEnd);
            }

            // se temporaryRule contiene almeno un carattere \p, allora è
            // necessario espandere la regola (singola linea)
            // in regole multiple (più di una linea). Caso di espansione verso exactMatch
            if (temporaryRule.contains("\\p")) {
                // if(temporaryRule.endsWith("\\p "))
                //     temporaryRule = temporaryRule.substring(0, temporaryRule.length()-3);
                temporaryRule = splitMultipleRule(temporaryRule);

            }

            if (temporaryRule.contains("(")) {
                // if(temporaryRule.endsWith("\\p "))
                //     temporaryRule = temporaryRule.substring(0, temporaryRule.length()-3);
                int index = temporaryRule.indexOf("(");
                while(temporaryRule.charAt(index) != ' ' ) {
                    index--;
                }
                temporaryRule = temporaryRule.substring(0, index++) + " \"" + temporaryRule.substring(index++);
                // temporaryRule = temporaryRule.replace("(", "\"(");
                temporaryRule = temporaryRule.replace(")", ")\"");

            }


            // controllo se la sintassi della frase
            Boolean isRuleCorrect = checkRule();
            if (temporaryRule != "" && isRuleCorrect) {

                if (ecr) {
                    this.temporaryRule = this.temporaryRule.concat("\n");
                }
                if (myEndString != null) {
                    this.temporaryRule = this.temporaryRule + myEndString;
                }

                System.out.println("[Rule #" + ruleId + "] Translated.");
                // stampa su file

                /**
                 * Prima di salvare la regola tradotta nel TreeMap finalPolicies
                 * si controlla che tipo di resolutionStrategy la NSF in questione supporta
                 * al momento si supporta solo FirstMatchingRule
                 */
                String requiredResStrat = nsfPolicyDetail.resolutionStrategyInfo;
                if (requiredResStrat != null && requiredResStrat.equals("FMR")) {
                    if (externalDataValue != null) { // se la regola ha una priorità, la si usa come chiave nella map
                        Integer index = Integer.parseInt(this.externalDataValue);
                        while (finalPolicies.containsKey(index))
                            index += 1;
                        finalPolicies.put(index, this.temporaryRule);
                    } else {
                        /**
                         * se la regola non ha una priorità, viene usata come chiave interi superiori al
                         * numero delle regole
                         * in modo da non assumere come valore la priorità di eventuali regole
                         * successive
                         */
                        Integer index = ruleList.getLength() + finalPolicies.size();
                        while (finalPolicies.containsKey(index))
                            index += 1;
                        finalPolicies.put(index, this.temporaryRule);
                        // if(finalPolicies.containsKey(ruleList.getLength()))
                        // finalPolicies.put(ruleList.getLength()+finalPolicies.size(),
                        // this.temporaryRule);
                        // else
                        // finalPolicies.put(ruleList.getLength(), this.temporaryRule);
                    }
                    externalDataValue = null;
                } else if (requiredResStrat != null) {
                    // si ottengono le resolutionStrategy NOTE all'NSFTranslator
                    List<String> availableResStrat = getEnumerationLiterals("ResolutionStrategyEnumeration");
                    if (availableResStrat.contains(requiredResStrat)) // resStrat nota ma non supportata
                        System.out.println("ERROR: " + nsfName + " requires to use the available " + requiredResStrat
                                + " Resolution Strategy that NSFTranslator does not support.");
                    else // resStrat sconosciuta
                        System.out.println("ERROR: " + nsfName + " requires to use " + requiredResStrat
                                + " Resolution Strategy that is unknown to the NSFTranslator.");
                    break;
                } else {
                    /**
                     * In generale, le regole sono gestite utilizzando la dimensione della Map come
                     * chiave,
                     * quindi saranno inserite nell'ordine con cui sono processate
                     */
                    finalPolicies.put(finalPolicies.size(), this.temporaryRule);
                }

            } else {
                if (temporaryRule != "" && !isRuleCorrect)
                    System.out.println("[Rule #" + ruleId + "] SecurityCapability dependencies are not satisfied.");
                if (force) {
                    System.out.println("[Rule #" + ruleId + "] Rule is not correct, it will not be translated.");
                    this.temporaryRule = "";
                    requestedConditionOperator = null;
                    requestedActionOperator = null;
                    continue;
                } else {
                    finalPolicies.clear();
                    System.out.println("[Rule #" + ruleId + "] Rule is not correct, translation tool will stop.");
                    return;

                }
            }
        }

        NodeList defaultActionList = getNodelistOfElementFromDocumentByTagname(xmlRuleDocument,
                "defaultActionCapabilitySpec");

        // si inizializza temporaryRule con ruleStart (da NSFPolicyDetail)
        if (nsfPolicyDetail != null) {
            if (nsfPolicyDetail.ruleStart != null) {
                this.temporaryRule = nsfPolicyDetail.ruleStart;
            }
        }
        if (scr) {
            this.temporaryRule = this.temporaryRule.concat("\n");
        }
        this.temporaryCapability = "";
        String defaultActionRule = getDefaultActionRule(defaultActionList, destinationNSF);

        if (defaultActionRule != null)
            finalPolicies.put(Integer.MAX_VALUE, this.temporaryRule);

        for (String p : finalPolicies.values())
            this.printWriter.println(p);

        // Se NSFPolicyDetail richiede una keyword al termine del file, viene aggiunta
        if (nsfPolicyDetail != null && nsfPolicyDetail.policyTrailer != "" && nsfPolicyDetail.policyTrailer != null) {
            this.printWriter.println(nsfPolicyDetail.policyTrailer);
        }
        this.printWriter.close();
    }

    // genera la lista dei nodi da un documento rispetto ad un tagName
    private static NodeList getNodelistOfElementFromDocumentByTagname(Document d, String tagname) {
        return d.getElementsByTagName(tagname);
    }

    // genera il documento in base al path, relativo al progetto o globale se si
    // parte da C://
    private static Document generateDocument(String path) {
        DocumentBuilderFactory df;
        DocumentBuilder builder;
        df = DocumentBuilderFactory.newInstance();

        try {
            builder = df.newDocumentBuilder();
            return builder.parse(path);
        } catch (ParserConfigurationException e) {
            System.out.println("Error: " + e.getMessage());
            System.exit(0);
        } catch (SAXException e) {
            System.out.println("Error: " + e.getMessage());
            System.exit(0);
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
            System.exit(0);
        }
        return null;
    }

    // funzione che ritorna un oggetto NSFPolicyDetail contenente i dettagli
    // riguardo alla formazione delle regole per una specifica NSF
    private NSFPolicyDetail getNSFPolicyDetail(NodeList nsfList) {
        NSFPolicyDetail selectedNsfPolicyDetail = null;
        String ruleStart, ruleEnd, policyEncoding, policyTrailer, resolutionStrategyInfo, defaultSecurityCapability, capabilityStart, capabilityEnd;
        /**
         * Per ogni attributo nella rule, si crea una entry nell'HashMap ruleAttributeDetails
         * in cui: 
         * key: nome dell'attributo nella rule
         * value: HashMap -> set di mappings tra i possibili valori del rule attribute e l'effettivo valore da sostituire
         *          | key: possibile valore dell'attributo 
         * *        | value: valore da sostituire per l'attributo
         */
        HashMap<String, HashMap<String,String>> ruleAttributeDetails; 

        // itero la lista dei nodi nsf
        for (int j = 0; j < nsfList.getLength(); j++) {
            Element e1 = getElemenetIfDeferredElementImpl(nsfList.item(j));
            if (e1 == null)
                continue;

            String nsfId = e1.getAttribute("id");
            if (nsfId.equalsIgnoreCase(nsfName)) {
                // se ottengo il nodo della nsf di interessse
                NodeList nsfPolicyDetails = e1.getElementsByTagName("nsfPolicyDetails");
                for (int k = 0; k < nsfPolicyDetails.getLength(); k++) {
                    Element e2 = getElemenetIfDeferredElementImpl(nsfPolicyDetails.item(k));
                    if (e2 == null)
                        continue;
                    // si estraggono i campi di nsfPolicyDetails
                    ruleStart = getTextContextFromGetElementByTagName(e2, "ruleStart") + " ";
                    if(ruleStart != null && ruleStart.contains("null"))
                        ruleStart = "";
                    ruleEnd = getTextContextFromGetElementByTagName(e2, "ruleEnd");
                    if(ruleEnd != null && ruleEnd.contains("null"))
                        ruleEnd = "";
                    policyTrailer = getTextContextFromGetElementByTagName(e2, "policyTrailer");
                    if(policyTrailer != null && policyTrailer.contains("null"))
                        policyTrailer = "";
                    policyEncoding = getTextContextFromGetElementByTagName(e2, "policyEncoding");
                    if(policyEncoding != null && policyEncoding.contains("null"))
                        policyEncoding = "";
                    capabilityStart = getTextContextFromGetElementByTagName(e2, "capabilityStart");
                    if(capabilityStart != null && capabilityStart.contains("null"))
                        capabilityStart = "";
                    // si ottiene la resolution strategy della NSF corrente
                    resolutionStrategyInfo = getResolutionStrategy();

                    // si ottengono gli attributi policy richiesti dalla nsf corrente
                    List<String> requiredPolicyAttributes = getRequiredPolicyAttributes(e1);

                    // si ottengono gli attributi policy richiesti dalla nsf corrente
                    List<String> requiredRuleAttributes = getRequiredRuleAttributes(e1);
                    
                    // si ottengono le defaultAction supportate dalla NSF corrente 
                    List<String> supportedDefaultActions = getNSFsupportedDefaultAction(e1);

                    // si ottiene il valore di defaultSecurityCapability
                    defaultSecurityCapability = getTextContextFromGetElementByTagName(e2, "defaultSecurityCapability");

                    ruleAttributeDetails = getRuleAttributeDetailsHashMap(e1); 

                    selectedNsfPolicyDetail = new NSFPolicyDetail(ruleStart, ruleEnd, policyTrailer, policyEncoding,
                            resolutionStrategyInfo, defaultSecurityCapability,
                            requiredPolicyAttributes,requiredRuleAttributes, supportedDefaultActions, ruleAttributeDetails, capabilityStart);

                }
                break;
            }
        }
        return selectedNsfPolicyDetail;
    }

    /**
     * Funzione che cerca l'elemento ResolutionStrategy, contenente la corrispondenza 
     * tra NSF e la resolutionStrategy adottata
     */
    private String getResolutionStrategy() {
        for (int i = 0; i < this.translationNodes.getLength(); i++) {
            // System.out.println(i);

            // fattibile solo includendo la libreria relativa
            if (!(this.translationNodes.item(i) instanceof DeferredElementImpl)) {
                continue;
            }
            // questo elemento contiene la security capability con il relativo adapter
            Element e = (Element) this.translationNodes.item(i);

            // si ricava il nome della securityCapability a cui capabilityTranslationDetails
            // si riferisce
            Element eSecCap = (Element) e.getElementsByTagName("securityCapability").item(0);
            // si confronta con il nome della securityCapability che siamo cercando
            String ref = eSecCap.getAttribute("ref");

            // System.out.println("secCap = " + this.temporaryCapability + " ref secCap = "
            // + ref);

            if (ref.equalsIgnoreCase("ResolutionStrategyCapabilitySpec")) {
                // si prende il nome della nsf a cui capabilityTranslationDetails si riferisce
                Element eNSF = (Element) e.getElementsByTagName("nSF").item(0);
                // si confronta con la nsf nel file di istanza
                ref = eNSF.getAttribute("ref");

                // System.out.println("nsf = " + this.nsfName + " ref nsf = " + ref);

                if (ref.equalsIgnoreCase(this.nsfName))
                    // ritorna l'elemento corretto
                    return getTextContextFromGetElementByTagName(e, "resolutionStrategy");
            }
        }
        // System.out.println("Nessun riferimento trovato");
        return null;
    }

    /**
     * Funzione che ottiene supportedDefaultAction per ogni NSF 
     */
    private List<String> getNSFsupportedDefaultAction(Element e1) {
        // si ottengono le defaultAction supportate dalla NSF corrente
        NodeList supportedDefaultActionNL = e1.getElementsByTagName("supportedDefaultAction");
        List<String> supportedDefaultActions = new ArrayList<>();
        for (int z = 0; z < supportedDefaultActionNL.getLength(); z++) {
            Element elem = getElemenetIfDeferredElementImpl(supportedDefaultActionNL.item(z));
            if (elem == null)
                continue;
            NodeList filterActionCapabilityNL = elem.getElementsByTagName("filterActionCapability");
            for (int x = 0; x < filterActionCapabilityNL.getLength(); x++) {
                Element elem1 = getElemenetIfDeferredElementImpl(filterActionCapabilityNL.item(x));
                if (elem1 == null)
                    continue;
                String filterActionCapabilitySupp = elem1.getTextContent();
                if (filterActionCapabilitySupp != null)
                    supportedDefaultActions.add(filterActionCapabilitySupp);
            }
        }
        return supportedDefaultActions;
    }

    /**
     * Funzione che ricava da NSFPolicyDetails le informazioni di 
     * mapping tra i possibili valori che si possono usare nei 
     * vari attributi utilizzabli nel nodo rule
     */
    private HashMap<String,HashMap<String,String>> getRuleAttributeDetailsHashMap(Element e1) {
        HashMap<String,HashMap<String,String>> returnHMap = new HashMap<>(); 
        HashMap<String,String> innerHMap = new HashMap<>(); 

        // si ottiene la nodelist di elementi ruleAttributeDetails
        NodeList ruleAttributeDetailsNList = e1.getElementsByTagName("ruleAttributeDetails");
        for (int i = 0; i < ruleAttributeDetailsNList.getLength(); i++) {
            Element elem = getElemenetIfDeferredElementImpl(ruleAttributeDetailsNList.item(i));
            if (elem == null)
                continue;
            // per ogni elemento ruleAttributeDetails si ricava il nome dell'attributo a cui fa riferimento
            String ruleTypeName = elem.getAttribute("ref");
            // si istanzia un hashmap vuoto per indicare tutti i mapping per lo specifico attributo 
            innerHMap = new HashMap<>(); 
            NodeList mappingDetailsNList = elem.getElementsByTagName("mappingDetails");
            for (int j = 0; j < mappingDetailsNList.getLength(); j++) {
                // per ogni elemento mappingDetails
                String keyStr = null; 
                String valueStr = null;

                elem = getElemenetIfDeferredElementImpl(mappingDetailsNList.item(j));
                if (elem == null)
                    continue;
                NodeList mappingKeyValueNList = elem.getChildNodes();
                for (int k = 0; k < mappingKeyValueNList.getLength(); k++) {
                    // si ricavano i valori del mapping 
                    elem = getElemenetIfDeferredElementImpl(mappingKeyValueNList.item(k));
                    if (elem == null)
                        continue;
                    if(elem.getTagName().equals("key"))
                        keyStr = elem.getTextContent();
                    if(elem.getTagName().equals("value"))
                        valueStr = elem.getTextContent();
                }
                if(keyStr!=null && valueStr!=null) {
                    // si popola l'hashmap dell'attributo in questione 
                    innerHMap.put(keyStr, valueStr);
                }
            }
            returnHMap.put(ruleTypeName, innerHMap);
        }
        return returnHMap; 

    }
 
    // si cerca l'elemento policyAttribute, contenente il policyAttribute che la NSF richiede
    private List<String> getRequiredPolicyAttributes(Element e1) {
        // si ottengono gli attributi richiesti dalla nsf corrente
        NodeList policyAttributeNList = e1.getElementsByTagName("policyAttribute");
        List<String> requiredPolicyAttributes = new ArrayList<>();
        for (int z = 0; z < policyAttributeNList.getLength(); z++) {
            Element elem = getElemenetIfDeferredElementImpl(policyAttributeNList.item(z));
            if (elem == null)
                continue;
            NodeList attributeNameNList = elem.getElementsByTagName("attributeName");
            for (int x = 0; x < attributeNameNList.getLength(); x++) {
                Element elem1 = getElemenetIfDeferredElementImpl(attributeNameNList.item(x));
                if (elem1 == null)
                    continue;
                String attributeNameSupp = elem1.getTextContent();
                if (attributeNameSupp != null)
                    requiredPolicyAttributes.add(attributeNameSupp);
            }
        }
        return requiredPolicyAttributes;
    }

    // si cerca l'elemento ruleAttribute, contenente il ruleAttribute che la NSF richiede
    private List<String> getRequiredRuleAttributes(Element e1) {
        // si ottengono gli attributi richiesti dalla nsf corrente
        NodeList ruleAttributeNList = e1.getElementsByTagName("ruleAttribute");
        List<String> requiredRuleAttributes = new ArrayList<>();
        for (int z = 0; z < ruleAttributeNList.getLength(); z++) {
            Element elem = getElemenetIfDeferredElementImpl(ruleAttributeNList.item(z));
            if (elem == null)
                continue;
            NodeList attributeNameNList = elem.getElementsByTagName("attributeName");
            for (int x = 0; x < attributeNameNList.getLength(); x++) {
                Element elem1 = getElemenetIfDeferredElementImpl(attributeNameNList.item(x));
                if (elem1 == null)
                    continue;
                String attributeNameSupp = elem1.getTextContent();
                if (attributeNameSupp != null)
                    requiredRuleAttributes.add(attributeNameSupp);
            }
        }
        return requiredRuleAttributes;
    }

    // ritorna la stringa contenuta nell'elemento passato in base al tag passato
    private String getTextContextFromGetElementByTagName(Element e, String s) {

        NodeList nl = e.getElementsByTagName(s);
        for (int j = 0; j < nl.getLength(); j++) {
            Element e2 = getElemenetIfDeferredElementImpl(nl.item(j));
            if (e2 == null)
                continue;
            if (e2.getTextContent() == null)
                return null;
            else
                return e2.getTextContent();
        }
        return null;
    }

    /**
     * Funzione che ricava da NSFCatalogue i dettagli delle resolution strategies
     * supportate
     */
    private HashMap<String, String> findResolutionStrategyDetails(NodeList resolutionStrategyNodeList) {
        String resolutionStrategyName = null;
        String requiredExternalData = null;
        HashMap<String, String> returnMap = new HashMap<>();
        for (int i = 0; i < resolutionStrategyNodeList.getLength(); i++) {

            if (!(resolutionStrategyNodeList.item(i) instanceof DeferredElementImpl)) {
                continue;
            }
            Element e = (Element) resolutionStrategyNodeList.item(i);
            resolutionStrategyName = e.getElementsByTagName("resolutionStrategyName").item(0).getTextContent();
            requiredExternalData = e.getElementsByTagName("requiredExternalData").item(0).getTextContent();
            if (resolutionStrategyName != null && requiredExternalData != null)
                returnMap.put(resolutionStrategyName, requiredExternalData);

        }

        return returnMap;
    }

    // funzione che trova i nodi figli di un elemento e li salva in
    // temporaryCapabilityAndAttributes
    private void exploreElement(Element e) {
        // System.out.println(e.getNodeName());
        this.temporaryCapabilityAndAttributes = this.temporaryCapabilityAndAttributes.concat(e.getNodeName() + " ");
        if (e.hasChildNodes()) {
            recursivesearch(e);
        }
    }

    // funzione ricorsiva per avere tutti gli attributi di una capability
    // dall'elemento foglia fino alla capability madre
    private void recursivesearch(Element e) {
        NodeList nl = e.getChildNodes();

        for (int i = 0; i < nl.getLength(); i++) {
            Node n = nl.item(i);
            // System.out.println(i);
            if (!(n instanceof DeferredElementImpl)) { // fattibile solo includendo la libreria relativa
                continue;
            }
            e = (Element) n;
            // estraggo l'operatore utilizzato nella capability
            // if (e.getNodeName().equalsIgnoreCase("range")) {
            // requestedConditionOperator = e.getNodeName();

            // // this.temporaryCapabilityAndAttributes =
            // this.temporaryCapabilityAndAttributes.concat(requestedConditionOperator + " ");
            // }

            // in questo modo, è possibile ottenere il nome di ogni nodo
            // all'interno della capability utile per verificare quale operatore è
            // utilizzato nella rule
            this.temporaryCapabilityAndAttributes = this.temporaryCapabilityAndAttributes.concat(n.getNodeName() + " ");
            if (e.getChildNodes().getLength() == 1) {

                this.temporaryCapabilityAndAttributes = this.temporaryCapabilityAndAttributes
                        .concat(n.getTextContent() + " ");
                // System.out.println(this.temporaryCapabilityAndAttributes);

            } else
                recursivesearch(e);
        }
    }

    private String clauseConverter(String destinationNSF) {

        String destErr = ""; 

        String[] s = this.temporaryCapabilityAndAttributes.split(" ");
        // si salva in temporaryCapability il nome della capability che si sta
        // considerando
        // in questo momento
        this.temporaryCapability = s[0];

        // cerco l'adapter della capability
        this.myCapabilityTranslation = findElementoTranslationNodesByCapability();
        if (this.myCapabilityTranslation == null) {
            if(destinationNSF!=null)
                destErr = " for the requested destination NSF "+ destinationNSF; 

            System.out.println("[Rule #" + ruleId + "]" + " ERROR: " + temporaryCapability
                    + " capabilityTranslationDetails not available"+destErr+".");
            return null;
        }

        pre = getPre();
        if (pre == null) {
            return null;
        }
        mid = getMid();
        if (mid.contains("\\n")) {
            mid = mid.replace("\\n", System.lineSeparator());
        }
        if (mid == null) {
            return null;
        }
        /**
         * if(pre.isEmpty() && mid.equalsIgnoreCase(" ")) mid = "";
         */
        // System.out.println(pre+mid);
        body = getBody();
        if (body == null) {
            return null;
        }
        // System.out.println(pre+mid+body);
        post = getPost();
        if (post.contains("\\n")) {
            post = post.replace("\\n", System.lineSeparator());
        }
        if (post == null) {
            return null;
        }

        // if(!body.isEmpty() && mid.equalsIgnoreCase(" ")){
        // return pre+body+post;
        // }
        if (body.isEmpty() && post.isEmpty()) {
            return pre + mid;
        } else if (pre.isEmpty()) {
            if (mid.equalsIgnoreCase(" ")) {
                return body + post;
            }

        }
        // System.out.println(pre+mid+body+post);
        return pre + mid + body + post;
    }

    // cerca un elemento in base alla capability che si sta considerando in questo
    // momento
    private Element findElementoTranslationNodesByCapability() {
        for (int i = 0; i < this.translationNodes.getLength(); i++) {
            // System.out.println(i);

            // fattibile solo includendo la libreria relativa
            if (!(this.translationNodes.item(i) instanceof DeferredElementImpl)) {
                continue;
            }
            // questo elemento contiene la security capability con il relativo adapter
            Element e = (Element) this.translationNodes.item(i);

            // si ricava il nome della securityCapability a cui capabilityTranslationDetails
            // si riferisce
            Element eSecCap = (Element) e.getElementsByTagName("securityCapability").item(0);
            // si confronta con il nome della securityCapability che siamo cercando
            String ref = eSecCap.getAttribute("ref");

            // System.out.println("secCap = " + this.temporaryCapability + " ref secCap = "
            // + ref);

            if (ref.equalsIgnoreCase(this.temporaryCapability)) {
                // si prende il nome della nsf a cui capabilityTranslationDetails si riferisce
                Element eNSF = (Element) e.getElementsByTagName("nSF").item(0);
                // si confronta con la nsf nel file di istanza
                ref = eNSF.getAttribute("ref");

                // System.out.println("nsf = " + this.nsfName + " ref nsf = " + ref);

                if (ref.equalsIgnoreCase(this.nsfName))
                    // ritorna l'elemento corretto
                    return e;
            }
        }
        // System.out.println("Nessun riferimento trovato");
        return null;
    }

    private String getPre() {
        // definito dal command e quindi dalla possibilit� di negare il comando

        realCommandName.clear();
        commandAttributeNameCondition.clear();
        commandAttributeValueCondition.clear();
        commandAttributeCheck.clear();
        // qui mi interessano le informazioni contenute in commandName ed in deniable
        String preCommandName = "";
        String commandName = null;

        // System.out.println(this.temporaryCapabilityAndAttributes);
        String[] s = this.temporaryCapabilityAndAttributes.split(" ");

        //si controlla se l'NSF possiede una stringa da porre prima di ogni capability 
        if(nsfPolicyDetail.capabilityStart != null && nsfPolicyDetail.capabilityStart != "" 
            && !(s[0].equalsIgnoreCase("acceptActionCapability") || s[0].equalsIgnoreCase("rejectActionCapability") )) {
            String parameterName;
            String parameterValue = ""; 
            //si controlla se è presente un parametro di tipo % 
            preCommandName = nsfPolicyDetail.capabilityStart; 
            if(preCommandName.contains("%")){
                //si estrae il nome parametro desiderato
                parameterName = preCommandName.split("%")[1].split(" ")[0]; 
                if(parameterName.equalsIgnoreCase("counter")) {
                    parameterValue = "myacl"+aclCounter.toString(); 
                    aclCounter++; 
                    aclRuleCounter++; 
                }
                preCommandName = preCommandName.replace("%"+parameterName, parameterValue)+" ";

            }
        }

        

        // cerco il commandName
        NodeList commandNameList = this.myCapabilityTranslation.getElementsByTagName("commandName");

        Integer newOperatorIndex;
        String newOperator = null, supportRuleAttributeStr = null ;

        List<String> conditionOperatorEnumeration = new ArrayList<>();
        // se è utilizzato un operatore, è necessario controllare se richiede
        // l'utilizzo di un comando differente rispetto a quello specificato 
        // in myCapabilityTranslation
        if (requestedConditionOperator != null || requestedActionOperator == null) {

            // se la capability nella rule utilizza un operatore, si controlla se il command
            // name deve essere modificato

            BodyConcatenator bodyConcat = null;
            bodyConcatenatorNL = this.myCapabilityTranslation.getElementsByTagName("bodyConcatenator");
            
            //si ottengono i bodyConcatenator che il myCapabilityTranslation possiede
            bodyConcatenators = getCapabilityBodyConcatenators();
            
            // si ottiene lo specifico bodyConcatenator dell'operatore richiesto
            bodyConcat = getRequiredBodyConcat(bodyConcatenators, requestedConditionOperator);

            // se l'operatore è supportato e richiede l'uso di un nuovo CommandName
            if (bodyConcat != null && bodyConcat.commandNames != null) {
                
                //si controlla se nella regola è presente una condition per il command name 
                ArrayList<CommandName> commandNameAList = bodyConcat.commandNames;
                
                HashMap<String,String> conditionReqCommandName = null; 
                
                // per ogni command name del singolo bodyConcatenator
                for(CommandName cn : commandNameAList) {
                    //se c'è una condizione da verificare 
                    if(cn.commandNameCondition.size()>0) {
                        conditionReqCommandName = cn.commandNameCondition; 
                        // per ogni condizione da verificare
                        for (Map.Entry<String, String> entry : conditionReqCommandName.entrySet()) {
                            List<String> suppS = Arrays.asList(s);
                            //se la security capability contiene la stringa relativa all'attributo da controllare espresso nell'elemento commandNameCondition
                            if(suppS.contains(entry.getKey())) {
                                // si verifica se il valore di tale attributo (elemento successivo) nella regola
                                // coincida con il valore specificato nell'elemento commandNameCondition
                                String nextRuleValue = suppS.get(suppS.indexOf(entry.getKey())+1);
                                // se si, allora si usa il command name relativo alla condition
                                if(nextRuleValue.equals(entry.getValue()))
                                    commandName = cn.commandName;
                            }
                        }
                    } else {
                        //se non c'è una condizione da verificare, si prende direttamente il realCommandName indicato 
                        commandName = cn.commandName; 
                    }
                }                
            } else if (bodyConcat == null) { // se l'operatore non è supportato
                // se non è presente un bodyConcatenator per l'operator richiesto 
                // è necessario ricavare il commandName dell'operatore verso cui fare l'espansione

                // si verifica se nel NSFCatalogue è indicato un metodo di espansione preferito
                NodeList preferredExpansionMethod = this.myCapabilityTranslation
                        .getElementsByTagName("preferredExpansionMethod");

                for (int i = 0; i < preferredExpansionMethod.getLength(); i++) {
                    Element e1 = getElemenetIfDeferredElementImpl(preferredExpansionMethod.item(i));
                    if (e1 == null)
                        continue;

                    // nel nodo preferredExpansionMethod possono essere presenti più nodi
                    // expansionMethod
                    NodeList expansionMethod = e1.getElementsByTagName("expansionMethod");
                    for (int j = 0; i < expansionMethod.getLength(); i++) {

                        Element e2 = getElemenetIfDeferredElementImpl(expansionMethod.item(j));
                        if (e2 == null)
                            continue;

                        String fromOperator = getTextContextFromGetElementByTagName(e2, "fromOperator");
                        // si salva il nome dell'operatore verso cui è preferito eseguire l'espansione
                        if (fromOperator.equals(requestedConditionOperator)) {
                            newOperator = getTextContextFromGetElementByTagName(e2, "toOperator");
                            bodyConcat = getRequiredBodyConcat(bodyConcatenators, newOperator);
                        }
                    }
                }

                // se non è stato trovato un operatore verso cui espandere preferito
                // allora cerca l'operator da sostituire immediatamente precedente
                if (bodyConcat == null || newOperator == null) {
                    conditionOperatorEnumeration = getEnumerationLiterals("SupportedConditionOperatorEnumeration");
                    if (conditionOperatorEnumeration == null)
                        return null;

                    newOperatorIndex = conditionOperatorEnumeration.lastIndexOf(requestedConditionOperator) - 1;

                    // ciclo while che itera dal "maggiore" al "minore" (vedi ordinamento degli
                    // operatori)
                    // finché non si trova un bodyConcatenator rispettivo
                    Boolean cont = true;
                    while (newOperatorIndex > -1 && cont) {
                        newOperator = conditionOperatorEnumeration.get(newOperatorIndex);

                        bodyConcat = getRequiredBodyConcat(bodyConcatenators, newOperator);

                        if (bodyConcat == null)
                            newOperatorIndex -= 1;
                        else
                            cont = false;
                    }
                }


                if (bodyConcat != null && bodyConcat.commandNames != null) {
                    // si controlla se nella regola è presente una condition per il command name
                    // vedere commenti sopra

                    ArrayList<CommandName> commandNameAList = bodyConcat.commandNames;

                    HashMap<String, String> conditionReqCommandName = null;

                    for (CommandName cn : commandNameAList) {
                        if (cn.commandNameCondition.size() > 0) {
                            conditionReqCommandName = cn.commandNameCondition;
                            for (Map.Entry<String, String> entry : conditionReqCommandName.entrySet()) {
                                List<String> suppS = Arrays.asList(s);
                                if (suppS.contains(entry.getKey())) {
                                    String nextRuleValue = suppS.get(suppS.indexOf(entry.getKey()) + 1);
                                    if (nextRuleValue.equals(entry.getValue()))
                                        commandName = cn.commandName;
                                }
                            }
                        } else {
                            commandName = cn.commandName;
                        }
                    }
                }
            }

        }
        // se dall'if precedente commandName non è stato popolato da newCommandName in
        // bodyConcat
        // (es: non è necessario un nuovo CommandName -> si usa quello della capability)
        // oppure
        // se non è richiesto un operatore (funzionamento versione tool precedente)
        // oppure 
        // l'NSF richiede di inizializzare commandName con un valore di default
        if (requestedConditionOperator == null || commandName == null || nsfPolicyDetail.capabilityStart != null) {
            // se non è richiesto un operatore o se è richiesto ma newCommandName è
            // vuoto
            for (int i = 0; i < commandNameList.getLength(); i++) {
                Element e1 = getElemenetIfDeferredElementImpl(commandNameList.item(i));
                if (e1 == null)
                    continue;

                // si chiama la funzione che mi prende il contenuto di realCommandName e si
                // inserisce nella lista (sia che sia null sia che non lo sia)
                realCommandName.add(getTextContextFromGetElementByTagName(e1, "realCommandName"));

                // si chiama la funzione che mi prende il contenuto di
                // commandAttributeNameCondition e si inserice nella lista (sia che sia null
                // sia che non lo sia)
                commandAttributeNameCondition.add(getTextContextFromGetElementByTagName(e1, "attributeName"));

                // si chiama la funzione che mi prende il contenuto di
                // commandAttributeValueCondition e si inserice nella lista (sia che sia null
                // sia che non lo sia)
                commandAttributeValueCondition.add(getTextContextFromGetElementByTagName(e1, "attributeValue"));

                // si recupera il nome della funzione da chiamare sul valore della capability  
                commandAttributeCheck.add(getTextContextFromGetElementByTagName(e1, "attributeCheck"));

                // si ottiene il valore di un eventuale rule attribute richiesto
                supportRuleAttributeStr = getTextContextFromGetElementByTagName(e1, "supportRuleAttribute");

            }
            /**
             * for(int i = 0; i < realCommandName.size();i++) {
             * if(!realCommandName.isEmpty()) System.out.println("nome nella lista "
             * +realCommandName.get(i)); if(!commandAttributeNameCondition.isEmpty())
             * System.out.println("commandAttributeNameCondition nella lista "
             * +commandAttributeNameCondition.get(i));
             * if(!commandAttributeValueCondition.isEmpty())
             * System.out.println("commandAttributeValueCondition nella lista "
             * +commandAttributeValueCondition.get(i)); }
             */


            // se la capability ha bisogno di un attributo in rule
            if(supportRuleAttributeStr!=null) {
                if(ruleAttributeValues.containsKey(supportRuleAttributeStr)) {
                    // si ottiene il valore dell'attributo nella rule fortnita
                    String ruleAttributeValue = ruleAttributeValues.get(supportRuleAttributeStr);
                    // si controlla se il valore di tale attributo deve essere sostituito da un valore specifico per la NSF selezionata
                    if(nsfPolicyDetail!=null && nsfPolicyDetail.ruleAttributeDetails.containsKey(supportRuleAttributeStr)){
                        HashMap<String,String> innerHMap = nsfPolicyDetail.ruleAttributeDetails.get(supportRuleAttributeStr); 
                        if(innerHMap.containsKey(ruleAttributeValue))
                            return innerHMap.get(ruleAttributeValue);
                        else    
                            return ruleAttributeValue;
                    } else {
                        // non è richiesta alcuna sostituzione, si ritorna il valore fornito nella rule
                        return ruleAttributeValue;
                    }
                } else {
                    // attributo necessario ma non presente nel nodo policy, errore
                    System.out.println("[Rule #" + ruleId + "]" + " ERROR: " + s[0] + " requires rule attribute "
                            + supportRuleAttributeStr + " but it is not found.");
                    return null;
                }
            } 
            // si controla la clausola operazione, da quella si deduce il comando ed in caso
            // se
            // negato. FINE.
            // perch� anche nel caso di pi� commandName la lista dovr� restituire quel
            // command name relativo a quella condition.

            // per ogni comando conosciuto per questa capability
            for (int i = 0; i < realCommandName.size(); i++) {
                // controlla se esiste una condizione per quel comando
                if (commandAttributeNameCondition.get(i) == null)
                    // se non esiste continua il ciclo
                    continue;
                // se esiste controlla se � contenuta nella stringa dei parametri passati
                // riguardanti la clausola
                if (this.temporaryCapabilityAndAttributes.contains(commandAttributeNameCondition.get(i))) {

                    for (int j = 0; j < s.length - 1; j++) { // se � presente allora cerco nella stringa splittata
                        // qual'� il
                        // valore relativo
                        // che sar� nella casella del vettore successiva a lui. (-1 perch� deve avere un
                        // valore, che � scritto dopo)
                        if (s[j].contentEquals(commandAttributeNameCondition.get(i))) { // se trovo lo stesso parametro
                            if (s[j + 1].contentEquals(commandAttributeValueCondition.get(i))) { // se � presente quel
                                // parametro (s[i+1])
                                // controlla che sia lo
                                // stesso necessario a
                                // questo comando
                                return preCommandName+realCommandName.get(i); // ho trovato il commandName che cercavo
                            }
                        }
                    }
                }
            }
            if (commandName == null) {
                for (int i = 0; i < realCommandName.size(); i++) {
                    // controlla se esiste un comando "di default" che pu� essere quello senza
                    // condizioni di utilizzo o quello che contiene come condizione "EQUAL_TO"
                    if (commandAttributeValueCondition.get(i) == null
                            || commandAttributeValueCondition.get(i).contentEquals("EQUAL_TO")) {
                        return preCommandName+realCommandName.get(i);
                    }
                }
            }
        }

        return preCommandName+commandName;
    }
    
    private String getMid() {
        // definito da internalClauseConcatenator
        String mid = getTextContextFromGetElementByTagName(this.myCapabilityTranslation, "internalClauseConcatenator");
        if (mid == null) {
            return " "; // mid di default tra il pre e il body
        }
        return mid;
    }

    private String getBody() {
        // definito da body concatenator se ci sono pi� parametri
        // si iterano tutti gli elementi di s, se si trova un elemento che pu� avere il
        // concatenatore allora si inserisce,
        // altrimenti non si inserisce nulla e si passa al concatenatore dopo, finché
        // nessun
        // concatenatore rispetta quella s[i]
        // o non è stato passato il concatenatore tra quelle due pre e post

        // ---- PRIMA FASE: si ricava da NSFCatalogue il capabilityTranslationDetails
        // della
        // securityCapability utilizzate nella rule in questione
        String body = "";
        // System.out.println(this.temporaryCapabilityAndAttributes);
        String[] s = this.temporaryCapabilityAndAttributes.split(" ");

        // si cerca i bodyConcatenator
        // NodeList bodyConcatenator =
        // this.myCapabilityTranslation.getElementsByTagName("bodyConcatenator");
        // System.out.println(this.temporaryCapability);

        // Map che tiene in considerazione di quali attributi devono rispettare una
        // regex indicata nel capabilityTranslationDetail
        attributeRegexMap = new HashMap<String, String>();
        attributeTransformMap = new HashMap<String, String>();
        attributeFromToMap = new HashMap<String, List<List<Integer>>>();
        // List<BodyConcatenator> bodyConcatenators = new ArrayList<>();
        // si cerca il bodyValueRestriciton
        NodeList bodyValueRestricitonNodeList = this.myCapabilityTranslation
                .getElementsByTagName("bodyValueRestriciton");

        // variabile di supporto per rappresentare l'elemento bodyConcatenator
        BodyConcatenator bodyConcat = null, supportBodyConcat = null;
        // Vvriabile a cui sono aggiunti i valori dei parametri per ogni security
        // capability
        ArrayList<String> values = new ArrayList<>();

        // per ogni bodyValueRestriciton, si salva in variabili locali i rispettivi
        // child
        // elements
        for (int i = 0; i < bodyValueRestricitonNodeList.getLength(); i++) {
            // si ottiene la restriction i-esima
            Element bodyValueType = getElemenetIfDeferredElementImpl(bodyValueRestricitonNodeList.item(i));
            if (bodyValueType == null)
                continue;
            String regexValue = null, attributeName = null, transform = null;

            // si cerca il attributeName a cui la bodyValueRestriciton fa riferimento
            NodeList nl = bodyValueType.getElementsByTagName("attributeName");
            for (int j = 0; j < nl.getLength(); j++) {
                Element e2 = getElemenetIfDeferredElementImpl(nl.item(j));
                if (e2 == null)
                    continue;
                attributeName = e2.getTextContent();
            }

            // si cerca il regexValue all'interno della bodyValueRestriciton esaminata
            nl = bodyValueType.getElementsByTagName("regexValue");
            for (int j = 0; j < nl.getLength(); j++) {
                Element e2 = getElemenetIfDeferredElementImpl(nl.item(j));
                if (e2 == null)
                    continue;
                regexValue = e2.getTextContent();
            }
            if (regexValue != null) {
                // System.out.println("l'attributo: "+attributeName+" deve rispettare questa
                // regex: "+regexValue);
                // inserisco nella mappa il nome dell'attributo e la sua regex, se esistono
                // restrizioni
                attributeRegexMap.put(attributeName, regexValue);
            }

            List<List<Integer>> allFromToList = new ArrayList<List<Integer>>();
            // si cerca l'integerRange all'interno della bodyValueRestriciton esaminata
            nl = bodyValueType.getElementsByTagName("integerRange");
            for (int j = 0; j < nl.getLength(); j++) {
                List<Integer> fromToList = new ArrayList<Integer>();
                Element e2 = getElemenetIfDeferredElementImpl(nl.item(j));
                if (e2 == null)
                    continue;
                String from, to;
                // si prende il campo from di integerRange
                NodeList fromNL = e2.getElementsByTagName("from");
                from = fromNL.item(0).getTextContent();
                // si prende il campo to di integerRange
                NodeList toNL = e2.getElementsByTagName("to");
                to = toNL.item(0).getTextContent();

                if (Integer.valueOf(from) <= Integer.valueOf(to)) {
                    fromToList.add(Integer.valueOf(from));
                    fromToList.add(Integer.valueOf(to));
                    // System.out.println(attributeName+ " " +from+"-"+to);
                } else if (Integer.valueOf(from) > Integer.valueOf(to)) {
                    fromToList.add(Integer.valueOf(to));
                    fromToList.add(Integer.valueOf(from));
                    // System.out.println(attributeName+ " " +to+"-"+from);
                }

                allFromToList.add(fromToList);
            }
            if (allFromToList.size() > 0) {
                // si aggiunge alla mappa il nome delle amia capability e la sua lista di liste
                // di
                // range
                attributeFromToMap.put(attributeName, allFromToList);

            }

            // si cerca il transform all'interno di bodyValueRestriciton
            nl = bodyValueType.getElementsByTagName("transform");
            for (int j = 0; j < nl.getLength(); j++) {
                Element e2 = getElemenetIfDeferredElementImpl(nl.item(j));
                if (e2 == null)
                    continue;
                transform = e2.getTextContent();
            }
            if (transform != null) {
                // System.out.println("l'attributo: "+attributeName+" deve fare questa
                // transform: "+transform);
                // si inserisce nella mappa il nome dell'attributo e la transform da fare su di
                // esso, se esiste
                attributeTransformMap.put(attributeName, transform);
            }

        }

        // Importante: i bodyConcatenator sono già ottenuti nel metodo getPre() nel caso
        // in cui si richiede l'uso di un operatore
        if (requestedConditionOperator == null || requestedActionOperator == null) {

            bodyConcat = null;
            bodyConcatenatorNL = this.myCapabilityTranslation.getElementsByTagName("bodyConcatenator");
            bodyConcatenators = getCapabilityBodyConcatenators();
        }
        /**
         * for(int i = 0; i < realConcatenator.size();i++) {
         * if(!realConcatenator.isEmpty())
         * System.out.println("realConcatenator nella lista " +realConcatenator.get(i));
         * if(!preVariable.isEmpty()) System.out.println("preVariable nella lista "
         * +preVariable.get(i)); if(!postVariable.isEmpty())
         * System.out.println("postVariable nella lista " +postVariable.get(i)); }
         */

        /**
         * si controlla se la capability corrente ha indicato che ha necessità
         * di un attributo di policy nel rispettivo bodyConcatenator
         */
        String supportPolicyAttribute = null;
        String concatSuppPolWithCapaValue = null;
        for (BodyConcatenator bc : bodyConcatenators) {
            if (bc.supportPolicyAttribute != null)
                supportPolicyAttribute = bc.supportPolicyAttribute;
            if (bc.concatSuppPolWithCapaValue != null)
                concatSuppPolWithCapaValue = bc.concatSuppPolWithCapaValue;

        }

        // ---- Fine prima fase di retrieve di capabilityTranslationDetails

        // allCapas definita fuori da getAllClauseAttributesName e getRegex in
        // modo da non doverlo fare in ogni ciclo del for
        allCapas = getNodelistOfElementFromDocumentByTagname(generateDocument(this.xsdLanguage), "xs:complexType");
        // si crea una lista che mi conterrà i possibili nomi dei campi
        // a partire dalla definizione della security capability in language.xsd
        List<String> clauseAttributesName = getAllClauseAttributesName(this.temporaryCapability, allCapas);

        // Variabili di supporto usate per salvare il valore dei parametri IN SEGUITO
        // alla validazione rispetto a eventuali bodyValueRestriciton
        String validatedParameterA = null, validatedParameterB = null;
        // System.out.println(clauseAttributesName);

        // System.out.println(clauseAttributesName + " " + realConcatenator);

        
        List<String> conditionOperatorEnumeration = getEnumerationLiterals("SupportedConditionOperatorEnumeration");
        // è necessario controllare se all'interno della regola è usato un operatore ma
        // non è stato specificato come
        // attributo operator della securityCapability
        Boolean ruleUseConditionOperator = Arrays.stream(s).anyMatch(conditionOperatorEnumeration.toString()::contains);

        List<String> actionOperatorEnumeration = getEnumerationLiterals("SupportedActionOperatorEnumeration");
            // è necessario controllare se all'interno della regola è usato un operatore ma
            // non è stato specificato come
            // attributo operator della securityCapability
        Boolean ruleUseActionOperator = Arrays.stream(s).anyMatch(actionOperatorEnumeration.toString()::contains);


        if(capabilityType.equalsIgnoreCase("condition")) {
            if (ruleUseConditionOperator && requestedConditionOperator == null) {
                System.out.println("[Rule #" + ruleId + "]" + " ERROR: " + s[0]
                        + " uses an operator but it is not stated in the securityCapability node.");
                return null;
            } else if (!ruleUseConditionOperator && requestedConditionOperator != null) {
                System.out.println("[Rule #" + ruleId + "]" + " ERROR: Operator is stated in the securityCapability node "
                        + s[0] + " but it does not use an operator.");
                return null;
            }
        } else if(capabilityType.equalsIgnoreCase("action")) {
            if (ruleUseActionOperator && requestedActionOperator == null) {
                System.out.println("[Rule #" + ruleId + "]" + " ERROR: " + s[0]
                        + " uses an operator but it is not stated in the securityCapability node.");
                return null;
            } else if (!ruleUseActionOperator && requestedActionOperator != null) {
                System.out.println("[Rule #" + ruleId + "]" + " ERROR: Operator is stated in the securityCapability node "
                        + s[0] + " but it does not use an operator.");
                return null;
            }
        }
            

        // se la regola non richiede l'uso di un operatore
        if (requestedConditionOperator == null && requestedActionOperator == null) { // eseguo la versione precedente del codice
            // System.out.println("1) "+body);
            // per ogni elemento nella stringa che contiene la capability incontrata nella
            // regola e i suoi attributi
            body = getBodyDetails(body, s, clauseAttributesName); 
            
        } else { // gestione dei nuovi operatori se la regola lo richiede

            if(requestedConditionOperator != null) {

                // si controlla che il primo operatore nella regola corrisponda a quello
                // richiesto
                List<String> operatorList = getEnumerationLiterals("SupportedConditionOperatorEnumeration");
                for (int y = 0; y < s.length; y++) {
                    if (s[y].equals(requestedConditionOperator))
                        break;
                    else {
                        for (String op : operatorList) {
                            if (s[y].equals(op)) {
                                System.out.println(
                                        "[Rule #" + ruleId + "]" + " WARNING: Operator mismatch in: " + s[0] + ".");
                                return null;
                            }
                        }
                    }

                }

                // si cerca il bodyConcatenator richiesto
                bodyConcat = getRequiredBodyConcat(bodyConcatenators, requestedConditionOperator);

                if (bodyConcat != null) { // si è trovato un bodyConcatenator per l'operatore richiesto

                    // si iterano i nomi dei nodi all'interno della regola
                    for (int j = 0; j < s.length; j++) {
                        // se si incontra un preVariable del bodyConcatenator richiesto
                        if (s[j].equalsIgnoreCase(bodyConcat.preVariable)
                                || s[j].equalsIgnoreCase(bodyConcat.postVariable)) {

                            /**
                             * In alcuni casi, i valori delle capability possono avere delle virgolette (");
                             * ciò rende inesatto il retrieve dell'intera stringa.
                             * Se si incontrano delle virgolette, si ricostruisce la stringa
                             */
                            if (s[j + 1].contains("\\b")) {
                                s[j+1] = s[j+1].replace("\\b", " ");
                            }
                            // si controlla se l'elemento successivo sia il valore del parametro (tramite
                            // regexp nel modello o in bodyValueRestriction)
                            Integer nextElementType = isCorrectType(s[j], s[j + 1]);

                            // esiste la regex per il parametro e il valore usato la rispetta
                            if (nextElementType == 1) {
                                // il valore viene validato con validateParameter e aggiunto alla lista dei
                                // valori
                                values.add(validateParameter(s[j], s[j + 1]));
                            } else if (nextElementType == 0) {
                                // esiste la regex per il parametro e il valore usato NON la rispetta
                                System.out.println("[Rule #" + ruleId + "]" + " ERROR: Parameter \"" + s[j] + "\" in "
                                        + temporaryCapability + " does not satisfy the required regular expression.");
                                return null;
                            } else if (nextElementType == -1) {
                                // nessuna regex per il parametro indicato
                                // se è un inner operator
                                if (conditionOperatorEnumeration.contains(s[j + 1])) {
                                    // si prova a cercare il bodyConcatenator dell'operatore interno
                                    supportBodyConcat = null;

                                    supportBodyConcat = getRequiredBodyConcat(bodyConcatenators, s[j + 1]);

                                    if (supportBodyConcat != null) { // se il bodyConcatenator esiste
                                        validatedParameterA = null;
                                        validatedParameterB = null;
                                        // si itera a partire dall'indice corrente in quanto potrebbero esserci più
                                        // elementi uguali
                                        for (int k = j + 1; k < s.length; k++) {
                                            if (s[k].equals(supportBodyConcat.preVariable)) {
                                                // si suppone che l'elemento successivo al parametro sia il rispettivo
                                                // valore
                                                validatedParameterA = validateParameter(supportBodyConcat.preVariable,
                                                        s[k + 1]);
                                            }
                                            if (s[k].equals(supportBodyConcat.postVariable)) {
                                                validatedParameterB = validateParameter(supportBodyConcat.postVariable,
                                                        s[k + 1]);
                                            }
                                            if (validatedParameterA != null && validatedParameterB != null)
                                                break;
                                        }

                                        if (validatedParameterA != null && validatedParameterB != null) {
                                            if(supportBodyConcat.postConcatenator == null)
                                                values.add(validatedParameterA + supportBodyConcat.realConcatenator + validatedParameterB);
                                            else 
                                                values.add(validatedParameterA + supportBodyConcat.realConcatenator + validatedParameterB + supportBodyConcat.postConcatenator); 
                                        }
                                        else
                                            return null;

                                    } else {
                                        /**
                                         * nessun bodyConcatenator per l'operatore richiesto
                                         * L'operazione di espansione non è supportata per gli operatori interni ad
                                         * altri operatori
                                         * es: union(elementRange(start, end), elementValue, elementValue) con
                                         * operatore range non disponibile
                                         */
                                        System.out.println(
                                                "[Rule #" + ruleId + "]" + " ERROR: Cannot translate inner operator "
                                                        + s[j + 1] + " in " + s[0] + ".");
                                        return null;
                                    }
                                } else {
                                    /**
                                     * Potrebbe dare problemi in futuro!
                                     * Non esiste una regex per il parametro indicato e
                                     * il valore del parametro ( successivo a preVariable o postVariable)
                                     * non è un operatore interno.
                                     * Per integrare in maniera semplice l'uso di operatori alle securityCapability
                                     * preesistenti si assume a questo punto che il valore del parametro sia un
                                     * valore ammesso
                                     * (senza fare ulteriori controlli).
                                     * Soluzione più sicura: aggiungere, in bodyValueRestriction per ogni
                                     * securityCapability,
                                     * una regex che rappresenta il valore ammesso per il parametro in questione.
                                     */

                                    if (regexAssumption) {
                                        // System.out.println("[Rule #"+ruleId+"]"+" WARNING: Certain capability
                                        // parameters have been considered correct even if they do not have any
                                        // associated regular expression.\nTo avoid this behaviour, please add a regular
                                        // expression in the correspondent bodyConcatenator.");
                                        regexAssumption = false;
                                    }
                                    values.add(validateParameter(s[j], s[j + 1]));

                                }

                            }
                        }

                    }
                } else { // nessun bodyConcatenator per l'operatore richiesto, espansione necessaria

                    // se non è presente un bodyConcatenator per l'operator richiesto

                    Integer newOperatorIndex;
                    String newOperator = null;

                    // si verifica se nel NSFCatalogue è indicato un metodo di espansione preferito
                    NodeList preferredExpansionMethod = this.myCapabilityTranslation
                            .getElementsByTagName("preferredExpansionMethod");

                    for (int i = 0; i < preferredExpansionMethod.getLength(); i++) {
                        Element e1 = getElemenetIfDeferredElementImpl(preferredExpansionMethod.item(i));
                        if (e1 == null)
                            continue;

                        // nel nodo preferredExpansionMethod possono essere presenti più nodi
                        // expansionMethod
                        NodeList expansionMethod = e1.getElementsByTagName("expansionMethod");
                        for (int j = 0; i < expansionMethod.getLength(); i++) {

                            Element e2 = getElemenetIfDeferredElementImpl(expansionMethod.item(j));
                            if (e2 == null)
                                continue;

                            String fromOperator = getTextContextFromGetElementByTagName(e2, "fromOperator");
                            // si salva il nome dell'operatore verso cui è preferito eseguire l'espansione
                            if (fromOperator.equals(requestedConditionOperator)) {
                                newOperator = getTextContextFromGetElementByTagName(e2, "toOperator");
                                bodyConcat = getRequiredBodyConcat(bodyConcatenators, newOperator);
                            }
                        }
                    }

                    // se non è stato trovato un operatore verso cui espandere preferito
                    // allora si cerca l'operator da sostituire immediatamente precedente
                    if (bodyConcat == null || newOperator == null) {

                        // if(conditionOperatorEnumeration == null)
                        // return null;

                        newOperatorIndex = conditionOperatorEnumeration.lastIndexOf(requestedConditionOperator) - 1;

                        // ciclo while che itera dal "maggiore" al "minore" (vedi ordinamento degli
                        // operatori)
                        // finché non si trova un bodyConcatenator rispettivo
                        Boolean cont = true;
                        while (newOperatorIndex > -1 && cont) {
                            newOperator = conditionOperatorEnumeration.get(newOperatorIndex);

                            bodyConcat = getRequiredBodyConcat(bodyConcatenators, newOperator);

                            if (bodyConcat == null)
                                newOperatorIndex -= 1;
                            else
                                cont = false;
                        }
                    }
                    // se si è trovato un operatore precedente supportato dalla securityCapability
                    if (bodyConcat != null) {
                        // si costruisce il nome del metodo per applicare l'espansione necessaria
                        String methodName = "from" + requestedConditionOperator.substring(0, 1).toUpperCase()
                                + requestedConditionOperator.substring(1) + "To"
                                + bodyConcat.operatorType.substring(0, 1).toUpperCase()
                                + bodyConcat.operatorType.substring(1);
                        Object ret = executeDynamicMethod(methodName, (Object) s);
                       
                        // poiché astratto, è necessario verificare che l'output sia un ArrayList e che
                        // i suoi elementi siano String
                        if (ret instanceof ArrayList<?>) {
                            for (int i = 0; i < ((ArrayList<?>) ret).size(); i++) {
                                Object item = ((ArrayList<?>) ret).get(i);
                                if (item instanceof String) {
                                    values.add((String) item);
                                }
                            }
                        } else 
                            return null; 
                    } else {
                        // Non dovrebbe accadere mai; la securityCapability non supporta nulla
                        System.out
                                .println("FATAL ERROR: NSFCatalogue does not have any bodyConcatenator for " + s[0] + ".");
                        return null;
                    }

                }
            } else if (requestedActionOperator != null) {

                // si controlla che il primo operatore nella regola corrisponda a quello
                // richiesto
                List<String> operatorList = getEnumerationLiterals("SupportedActionOperatorEnumeration");
                for (int y = 0; y < s.length; y++) {
                    if (s[y].equals(requestedActionOperator))
                        break;
                    else {
                        for (String op : operatorList) {
                            if (s[y].equals(op)) {
                                System.out.println(
                                        "[Rule #" + ruleId + "]" + " WARNING: Operator mismatch in: " + s[0] + ".");
                                return null;
                            }
                        }
                    }

                }

                bodyConcat = getRequiredBodyConcat(bodyConcatenators, requestedActionOperator);
                if (bodyConcat != null && !requestedActionOperator.equalsIgnoreCase("proposal")) { // si è trovato un
                                                                                                   // bodyConcatenator
                                                                                                   // per l'operatore
                                                                                                   // richiesto

                    // si iterano i nomi dei nodi all'interno della regola
                    for (int j = 0; j < s.length; j++) {
                        // se si incontra un preVariable del bodyConcatenator richiesto
                        if (s[j].equalsIgnoreCase(bodyConcat.preVariable)
                                || s[j].equalsIgnoreCase(bodyConcat.postVariable)) {
                            // si controlla se l'elemento successivo sia il valore del parametro (tramite
                            // regexp nel modello o in bodyValueRestriction)
                            Integer nextElementType = isCorrectType(s[j], s[j + 1]);

                            // esiste la regex per il parametro e il valore usato la rispetta
                            if (nextElementType == 1) {
                                // il valore viene validato con validateParameter e aggiunto alla lista dei
                                // valori
                                values.add(validateParameter(s[j], s[j + 1]));
                            } else if (nextElementType == 0) {
                                // esiste la regex per il parametro e il valore usato NON la rispetta
                                System.out.println("[Rule #" + ruleId + "]" + " ERROR: Parameter \"" + s[j] + "\" in "
                                        + temporaryCapability + " does not satisfy the required regular expression.");
                                return null;
                            } else {
                                /**
                                 * non esiste la regex per il parametro, si assume che il valore successivo a
                                 * preVariable
                                 * non sia un inner operator e dunque il valore della security capability
                                 */

                                values.add(validateParameter(s[j], s[j + 1]));
                            }
                        }
                    }
                } else if (requestedActionOperator.equalsIgnoreCase("proposal")) {
                    // si ottiene un arrayList per identificare la posizione del preVariable
                    // all'interno della stringa s
                    String suppStr = String.join(" ", s);
                    ArrayList<String> props = new ArrayList<>(Arrays.asList(suppStr.split(bodyConcat.preVariable)));
                    props.remove(0);
                    // props contiene i singoli valori (insieme di stringhe identificato dalla
                    // presenza del preVariable)
                    // da concatenare con il requestedActionOperator
                    for (String propStr : props) {
                        // per ogni singolo valore da concatenare con il requestedActionOperator
                        // si chiama getBodyDetails per ottenere gli elementi del singolo valore
                        // formattati nel modo corretto
                        s = propStr.split(" ");
                        String newBody = "";
                        newBody = getBodyDetails(newBody, s, clauseAttributesName);
                        values.add(newBody);
                    }
                } else {
                    System.out.println("FATAL ERROR: NSFCatalogue does not have any " + requestedActionOperator
                            + " bodyConcatenator for " + s[0] + ".");
                    return null;
                }
            }
            // si concatenano i valori con il realConcatenator
            if (!values.isEmpty()) {
                for (String v : values) {
                    body = body.concat(v).concat(bodyConcat.realConcatenator);

                }
                if (bodyConcat.realConcatenator != "")
                    body = body.substring(0, body.length() - 1);
            } else
                return null;

        }

        // se il getBody non ha trovato il valore della capability e 
        // se la capability ha bisogno di un attributo di policy
        if ((body == null || body.equals("")) && supportPolicyAttribute != null) {
            // si ricava il valore di tale attributo del nodo policy
            if (policyAttributeValues.containsKey(supportPolicyAttribute)) {
                // se la capability contiene un solo nodo (caso AppendRuleActionCapability)
                if (s.length == 1) {
                    // getBody ritorna il valore dell'attributo
                    return policyAttributeValues.get(supportPolicyAttribute);
                } else {
                    /**
                     * se la capability ha più di un nodo ciò vuol dire che nella regola
                     * è stato fornito il valore della capability nonostante questa supporti
                     * supportPolicyAttribute
                     * 
                     * In capabilityTranslationDetails si usa il nodo concatSuppPolWithCapaValue
                     * che specifica se si desidera:
                     * - concatenare il policy attribute con il valore della capability fornito (if
                     * successivo)
                     * oppure
                     * - non si vogliono concatenare questi due valori ma
                     * 
                     */

                    if (concatSuppPolWithCapaValue != null && concatSuppPolWithCapaValue.equals("true"))
                        body = policyAttributeValues.get(supportPolicyAttribute);

                }

            } else {
                // attributo necessario ma non presente nel nodo policy, errore
                System.out.println("[Rule #" + ruleId + "]" + " ERROR: " + s[0] + " requires policy attribute "
                        + supportPolicyAttribute + " but it is not found.");
                return null;
            }

        }
        requestedConditionOperator = null;
        requestedActionOperator = null; 

        // si controlla se il valore della Security Capability determina la modifica del comando della stessa (String pre)
        // ciò avviene tramite una verifica sul valore fornito
        // se la funzione restituisce 
        // True  -> si modifica il commandName con quello fornito in realCommand name allo stesso indice 
        // False -> non si applica alcuna modifica
        // String supportBody = body.split("\\p")[0]; 
        int checkFunctionIndex = IntStream.range(0, commandAttributeCheck.size())
                                .filter(i -> commandAttributeCheck.get(i) != null)
                                .findFirst().orElse(-1);
        if(checkFunctionIndex>=0) {
            String checkFunction = commandAttributeCheck.get(checkFunctionIndex); 
            if(checkFunction != null) {
                Object ret = executeDynamicMethod(checkFunction, (Object) body); 
                if(ret instanceof Boolean) {
                    if((Boolean) ret)
                        if(pre.contains(" ")) {
                            String[] suppPre = pre.split(" "); 
                            suppPre[suppPre.length-1] = realCommandName.get(checkFunctionIndex);
                            pre = String.join(" ",suppPre);
                        } else 
                            pre = realCommandName.get(checkFunctionIndex); 
                }
            }
        }
        return body;
    }

    // stampa nella stringa di riferimento l'elemento che viene passato. vengono
    // stampati il tipo di capability che si sta considerando e gli attributi
    private List<String> getAllClauseAttributesName(String newTempCapa, NodeList allCapas) {
        List<String> attributes = new ArrayList<String>();
        // allCapas sono i nodi complexTypes da language.xsd

        // si cerca il complexType (da language.xsd)
        // della capability usata in rule instance
        for (int i = 0; i < allCapas.getLength(); i++) {
            Element e1 = getElemenetIfDeferredElementImpl(allCapas.item(i));
            if (e1 == null)
                continue;
            if (e1.getAttribute("name").equalsIgnoreCase(newTempCapa)) {
                // si trova la capability interessata
                NodeList nl2 = e1.getElementsByTagName("xs:element");
                // se la capability interessata ha dei child elements
                if (nl2.getLength() > 0) {
                    for (int j = 0; j < nl2.getLength(); j++) { // per ogni elemento nel complexType
                        Element e2 = getElemenetIfDeferredElementImpl(nl2.item(j));
                        if (e2 == null)
                            continue;
                        createListAttributes(allCapas, attributes, e2);
                    }
                } else {
                    // se la capability interessata, è estesa da un'altra capability
                    // se ne estrae il nome
                    Element parent = findExtensionElement(e1);
                    String[] nome = parent.getAttribute("base").split(":");
                    if (nome.length > 1) {
                        newTempCapa = nome[1];
                    } else {
                        newTempCapa = nome[0];
                    }
                    // System.out.println(newTempCapa.toString());
                    // si chiama getAllClauseAttributesName sulla capability extension
                    attributes = getAllClauseAttributesName(newTempCapa, allCapas);
                }
            }
        }
        return attributes;
    }

    // cerca se nei vari elementi interni all'elemento passato esiste un elemento
    // "xs:extension" ed in caso ritorna quello
    private Element findExtensionElement(Element e) {
        // l'attributo "base" dovrebbe essere solo in "extension" quindi quando si
        // trova, si trova anche l'extension
        String base = e.getAttribute("base");
        if (base != "") {
            return e;
        }
        if (!e.hasChildNodes()) {
            return null;
        }
        NodeList nodes = e.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            // fattibile solo includendo la libreria relativa
            if (!(nodes.item(i) instanceof DeferredElementImpl)) {
                continue;
            }
            return findExtensionElement((Element) nodes.item(i));
        }
        return null;
    }

    // crea in modo ricorsivo la lista degli attributi appartenenti all'elemento, se
    // l'elemento � un tipo complesso allora lo cerca
    private void createListAttributes(NodeList elementNL, List<String> ls, Element e) {

        int i;
        
        if (e.getAttribute("type") != "") { // Cerca il tipo dell'elemento nel language.xsd
            for (i = 0; i < elementNL.getLength(); i++) {
                Element e1 = getElemenetIfDeferredElementImpl(elementNL.item(i));
                if (e1 == null)
                    continue;
                if (e1.getAttribute("name").contentEquals(e.getAttribute("type"))) {
                    createListAttributes(elementNL, ls, e1);

                    break;
                }
            }
            if (i == elementNL.getLength()) { // || e.getNodeName().equals("xs:element")) { //Se il tipo non è presente
                // in language.xsd, allora estraggo il nome dell'attributo
                // System.out.println(e.getAttribute("name"));
                // aggiugo un nuovo elemento alla lista solo se non è già esistente
                if (!ls.contains(e.getAttribute("name")))
                    ls.add(e.getAttribute("name"));
                return;
            }
        }
        // ls.add(e.getAttribute("name"));

        NodeList nl = e.getElementsByTagName("xs:element");
        for (i = 0; i < nl.getLength(); i++) {
            Element e1 = getElemenetIfDeferredElementImpl(nl.item(i));
            if (e1 == null)
                continue;
            createListAttributes(elementNL, ls, e1);
        }
        return;
    }

    /**
     * Funzione che restituisce i valori di un enumeration
     */
    private List<String> getEnumerationLiterals(String enumerationName) {
        NodeList allSimpleTypes = getNodelistOfElementFromDocumentByTagname(generateDocument(this.xsdLanguage),
                "xs:simpleType");
        List<String> enumerationStrings = new ArrayList<>();

        // ciclo per popolare enumerationStrings
        for (int i = 0; i < allSimpleTypes.getLength(); i++) {
            Element e1 = getElemenetIfDeferredElementImpl(allSimpleTypes.item(i));
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
        return enumerationStrings;
    }

    private BodyConcatenator getRequiredBodyConcat(List<BodyConcatenator> bodyConcatenators, String requestedConditionOperator) {
        // Si iterano i bodyConcatenator a disposizione finché non si trova quello per
        // l'operatore richiesto
        BodyConcatenator bodyConcat = null;
        for (int k = 0; k < bodyConcatenators.size(); k++) {
            if (bodyConcatenators.get(k).operatorType != null
                    && bodyConcatenators.get(k).operatorType.equalsIgnoreCase(requestedConditionOperator)) {
                bodyConcat = new BodyConcatenator(bodyConcatenators.get(k));
                break;
            }
        }
        return bodyConcat;

    }

    /**
     * Funzione che riceve il nome del parametro e il valore e controlla se tale
     * valore rispetta la regexp assegnata al parametro
     * è in parte simile a validateParameter
     * Ritorna:
     * isCorrect = 1 se la regex esiste è valida per il valore dato
     * isCorrect = 0 se la regex esiste e non è valida per il valore dato
     * isCorrect = -1 se la regex non esiste
     * 
     */
    private Integer isCorrectType(String parameterName, String capabilityParameter) {

        Integer isCorrect = 0;

        String regex = getAttributeDefaultRegex(this.temporaryCapability, parameterName, allCapas);

        if (regex != null) {
            if (regexValidity(capabilityParameter, regex)) {
                // System.out.println("[Rule #"+ruleId+"]"+" ERROR: Parameter "+parameterName+"
                // in "+temporaryCapability+" does not satisfy the required regular
                // expression.");
                isCorrect = 1;
            }
        }

        if (attributeRegexMap.containsKey(parameterName)) {
            regex = attributeRegexMap.get(parameterName);
            if (regexValidity(capabilityParameter, regex)) {
                // System.out.println("[Rule #"+ruleId+"]"+" ERROR: Parameter "+parameterName+"
                // in "+temporaryCapability+" does not satisfy the required regular
                // expression.");
                isCorrect = 1;
            }

        }

        if (regex == null && !attributeRegexMap.containsKey(parameterName))
            isCorrect = -1;
        // System.out.println("[Rule #"+ruleId+"]"+" WARNING: Required regular
        // expression for "+parameterName+" in "+temporaryCapability);
        return isCorrect;

    }

    /**
     * funzione che valida il valore di un parametro utilizzato in una security
     * capability (in una rule)
     * rispetto a eventuale restrizioni descritte in language.xsd (vedi regex)
     * oppure in bodyValueRestrictions
     */
    private String validateParameter(String parameterName, String capabilityParameter) {
        String regex = getAttributeDefaultRegex(this.temporaryCapability, parameterName, allCapas);

        // è necessario controllare se l'attributo di nome s[i] ha una regex come
        // default value,
        // in caso applicarla a s[i+1]
        // il nome dell'attributo è in s[i]
        // il nome della capability è in this.temporaryCapability
        // si prende il default value che contiene la regex

        // System.out.println("la regex dell'attributo "+s[i]+" vale: "+regex);
        // se presente, si controlla se la regex di default è soddisfatta per l'elemento
        // successivo (aka il valore dell'attributo)
        if (regex != null) {
            if (!regexValidity(capabilityParameter, regex)) {
                System.out.println("[Rule #" + ruleId + "]" + " ERROR: Parameter " + parameterName + " in "
                        + temporaryCapability + " does not satisfy the required regular expression.");
                return null;
            } else {
                // System.out.println("regex rispettata");
            }

        }
        // si controlla, se c'è, la regex aggiuntiva (aka la regex presa da
        // capabilityTranslationDetails)
        if (attributeRegexMap.containsKey(parameterName)) {
            regex = attributeRegexMap.get(parameterName);
            if (!regexValidity(capabilityParameter, regex)) {
                System.out.println("[Rule #" + ruleId + "]" + " ERROR: Parameter " + parameterName + " in "
                        + temporaryCapability + " does not satisfy the additional regular expression.");
                // System.out.println("il parametro passato "+ s[i+1]+" non rispetta la regex
                // aggiuntiva del parametro " +regex);
                return null;
            } else {
                // System.out.println("regex aggiuntiva rispettata");
            }

        }

        // si controlla se sono rispettate le restrizioni sui valori inseribili INTERI
        if (attributeFromToMap.containsKey(parameterName)) {
            boolean foundRange = false;
            List<List<Integer>> integerRanges = attributeFromToMap.get(parameterName);
            for (int k = 0; k < integerRanges.size(); k++) {
                int from = integerRanges.get(k).get(0), to = integerRanges.get(k).get(1);
                // System.out.println(from+"-"+to);
                // se il range è rispettato, si esce dal for e si continua
                if (Integer.valueOf(capabilityParameter) >= from && Integer.valueOf(capabilityParameter) <= to) {
                    foundRange = true;
                    break;
                }
            }
            if (!foundRange) {
                return null;
            }
        }

        if (attributeTransformMap.containsKey(parameterName)) {
            String transform = attributeTransformMap.get(parameterName);
            String newValue = transformAttribute(capabilityParameter, transform);
            if (newValue == null) {
                // System.out.println("la trasformazione " +transform+ " non è presente tra
                // quelle che conosciamo");
                return null;
            } else
                capabilityParameter = newValue;
        }
        return capabilityParameter;

    }

    /**
     * Questa funzione è responsabile del retrieve dei valori delle capability
     * nell'ordine e con i concatenator corretti
     * È stata introdotta poiché lo stesso codice è stato usato sia nella traduzione
     * senza utilizzo degli operatori sia nel caso particolare di operatori con 
     * action capability (operator = proposal)
     */
    private String getBodyDetails(String bodyDetails, String[] s, List<String> clauseAttributesName) { 
        String validatedParameterA = ""; 
        for (int i = 0; i < s.length - 1; i++) {
            // si itera s che contiene tutti i parametri passati dall'xml dell'istanza della
            // regola
            for (int j = 0; j < clauseAttributesName.size(); j++) {

                // se si incontra uno degli attributi possibili
                if (s[i].contentEquals(clauseAttributesName.get(j))) {

                    // System.out.println("2) "+body);
                    if (bodyDetails == "") {
                        /**
                         * In alcuni casi, i valori delle capability possono avere delle virgolette (");
                         * ciò rende inesatto il retrieve dell'intera stringa. 
                         * Se si incontrano delle virgolette, si ricostruisce la stringa
                         */
                        if(s[i+1].contains("\"")) {
                            int l;
                            String newS = s[i+1]; 
                            for(l = i+2; l<s.length ; l++) {
                                if(!s[l].contains("\""))
                                    newS = newS.concat(" "+s[l]); 
                                else
                                    break; 
                            }
                            s[i+1] = newS.concat(" "+s[l]); 
                        }
                        // validateParameter è una nuova funzione per eliminare duplicazione
                        // del codice
                        validatedParameterA = validateParameter(s[i], s[i + 1]);
                        if (validatedParameterA != null)
                            bodyDetails = bodyDetails.concat(validatedParameterA);
                        else
                            return null;

                    } else { // se il body non è vuoto
                        for (int k = 0; k < bodyConcatenators.size(); k++) {
                            // si inserisce il realConcatenator (aka concatenatore tra elementi nella stessa
                            // cpability)
                            // System.out.println("3) "+body);
                            if (bodyConcatenators.get(k).postVariable != null
                                    && bodyConcatenators.get(k).preVariable != null) {
                                if (i > 2 && s[i].contentEquals(bodyConcatenators.get(k).postVariable)
                                        && s[i - 2].contentEquals(bodyConcatenators.get(k).preVariable)
                                        && !s[i - 1].contentEquals(s[i + 1])) {

                                    validatedParameterA = validateParameter(s[i], s[i + 1]);

                                    if (bodyConcatenators.get(k).postConcatenator == null)
                                        bodyDetails = bodyDetails.concat(
                                                bodyConcatenators.get(k).realConcatenator + validatedParameterA);
                                    else
                                        bodyDetails = bodyDetails.concat(bodyConcatenators.get(k).realConcatenator
                                                + validatedParameterA + bodyConcatenators.get(k).postConcatenator);
                                }
                            } else if (bodyConcatenators.get(k).preVariable != null
                                    && bodyConcatenators.get(k).postVariable == null) {
                                // caso in cui il bodyConcatenator ha solo preVariable
                                // ossia caso setPolicyActionCapability
                                if (s[i].contentEquals(bodyConcatenators.get(k).preVariable)) {

                                    validatedParameterA = validateParameter(s[i], s[i + 1]);

                                    if (validatedParameterA != null)
                                        bodyDetails = bodyDetails.concat(
                                                bodyConcatenators.get(k).realConcatenator + validatedParameterA);

                                }
                            }

                        }
                    }

                    break; // � importantissimo questo break perch� in clauseAttributesName ci possono
                    // essere doppioni! quindi questo ferma il ciclo dopo aver trovato per la prima
                    // volta quel valore (caso in cui ci sono doppioni verrebbero fatte pi� volte
                    // iterazioni e azioni non dovute)
                }
            }
        }

        return bodyDetails; 
    }

    // funzione che cerca in tutto il file del linguaggio l'attributo desiderato
    // della capability che si sta considerando e ne ritorna, se esiste, la regex
    // OLD: (NON � ricorsivo! va solo al primo livello del type
    // il metodo è attualmente ricorsivo, ripercorre la gerarchia
    // all'indietro
    // finché non si trova nessun extension element o un default regex value
    private String getAttributeDefaultRegex(String targetCapability, String attributeName, NodeList allCapas) {
        // si trova la capability interessata
        Element capa = getCapabilityElementFromNodeList(targetCapability, allCapas);
        String supportRegex = null;
        if (capa == null)
            return null;
        // System.out.println("capa: "+capa.getAttribute("name"));
        NodeList nl = capa.getElementsByTagName("xs:element");
        if (nl.getLength() > 0) {
            for (int j = 0; j < nl.getLength(); j++) {
                Element e = getElemenetIfDeferredElementImpl(nl.item(j));
                if (e == null)
                    continue;
                // System.out.println("e: "+e.getAttribute("name"));
                // se questo elemento contiene un defalut ed ha lo stesso nome richiesto si
                // ritorna
                // il default
                if (e.getAttribute("default") != "" && e.getAttribute("name").contentEquals(attributeName)) {
                    // System.out.println("return e.getattribute: "+e.getAttribute("default"));
                    return e.getAttribute("default");
                }

                Element e2 = getCapabilityElementFromNodeList(e.getAttribute("type"), allCapas);
                if (e2 == null)
                    continue;
                // System.out.println("e2: "+e2.getAttribute("name"));
                NodeList nl2 = e2.getElementsByTagName("xs:element");
                for (int i = 0; i < nl2.getLength(); i++) {
                    Element e3 = getElemenetIfDeferredElementImpl(nl2.item(i));
                    if (e3 == null)
                        continue;
                    // System.out.println("e3: "+e3.getAttribute("name"));
                    // se questo elemento contiene un default ed ha il nome dell'attributo cercato
                    if (e3.getAttribute("default") != "" && e3.getAttribute("name").contentEquals(attributeName)) {
                        // System.out.println("e3 default: "+e3.getAttribute("default"));
                        return e3.getAttribute("default");
                    } else if (e3.getAttribute("type") != null && !e3.getAttribute("type").startsWith("xs")) {
                        supportRegex = getAttributeDefaultRegex(e3.getAttribute("type"), attributeName, allCapas);
                        if (supportRegex != null)
                            return supportRegex;
                        else
                            continue;
                    } else
                        continue;
                }
            }
        } else {
            NodeList extensionNl = capa.getElementsByTagName("xs:extension");
            for (int j = 0; j < extensionNl.getLength(); j++) {
                Element e = getElemenetIfDeferredElementImpl(extensionNl.item(j));
                if (e == null)
                    continue;

                if (e.getAttribute("base") != "" && !(e.getAttribute("base").startsWith("Condition")||e.getAttribute("base").startsWith("Action")))
                    return getAttributeDefaultRegex(e.getAttribute("base"), attributeName, allCapas);
                else
                    return null;

            }
        }
        return null;
    }

    // cerca in una nodelist se esiste il tipo dell'elemento passato
    private Element getCapabilityElementFromNodeList(String securityCapability, NodeList nl) {
        for (int i = 0; i < nl.getLength(); i++) {
            Element e1 = getElemenetIfDeferredElementImpl(nl.item(i));
            if (e1 == null)
                continue;
            if (e1.getAttribute("name").equalsIgnoreCase(securityCapability)) {
                return e1;
            }
        }
        return null;
    }

    // verifica la validit� di value rispetto alla regex regex
    private boolean regexValidity(String value, String regex) {
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(value);
        return matcher.matches();
    }

    // verifica se la transform è tra quelle che sono state implementate
    private String transformAttribute(String value, String transform) {
        String newValue = null; 
        switch (transform) {
            case "removeAESTrailingNumbers":
                if (value.startsWith("aes")) {
                    newValue = value.substring(0, value.length() - 3);
                    return newValue;
                } else
                    return value;
            case "removeTrailingNumbers":
                newValue = value.replaceAll("\\d*$", "");
                return newValue;
            // case "convertToRegex": 
            //     if(value.contains("?")||value.contains("*")||value.contains("+")||value.contains("^")||value.contains("$")) //se è una regex, non si fa nulla
            //         return value;    
            //     //.foo.com -> ^.*\.foo\.com$
            //     else if (value.startsWith(".")) { //caso wildcard: tutti gli hostname in quel sottodominio (primo . incluso)
            //         System.out.println("[Rule #" + ruleId + "]" + " WARNING: " + this.temporaryCapability
            //         + " value has been converted in regular expression.");
            //         newValue = "^.*"+Pattern.quote(value)+"$";
            //         return newValue;
            //     } else {
            //         System.out.println("[Rule #" + ruleId + "]" + " WARNING: " + this.temporaryCapability
            //         + " value has been converted in regular expression.");
            //         newValue = "^"+Pattern.quote(value)+"$";
            //         return newValue;
            //     }
            default:
                return null;
        }
    }

    private List<BodyConcatenator> getCapabilityBodyConcatenators() {


        List<BodyConcatenator> bodyConcatenators = new ArrayList<>();
        // per ogni bodyConcatenator all'interno di capabilityTranslationDetails, si
        // salva
        // in un arraylist gli oggetti bodyConcatenator incontrati
        for (int i = 0; i < bodyConcatenatorNL.getLength(); i++) {
            String realConcatenator, preVariable, postVariable, postConcatenator, operatorType,
                    supportPolicyAttribute = null,
                    concatSuppPolWithCapaValue = null;
            ArrayList<CommandName> commandNames = new ArrayList<>();
            Element e1 = getElemenetIfDeferredElementImpl(bodyConcatenatorNL.item(i));
            if (e1 == null)
                continue;
            // if (!e1.getAttribute("operator").equals("")) {
            // supportedOperators.add(e1.getAttribute("operator"));
            // }

            realConcatenator = getTextContextFromGetElementByTagName(e1, "realConcatenator");
            preVariable = getTextContextFromGetElementByTagName(e1, "preVariable");
            postVariable = getTextContextFromGetElementByTagName(e1, "postVariable");
            postConcatenator = getTextContextFromGetElementByTagName(e1, "postConcatenator");
            operatorType = getTextContextFromGetElementByTagName(e1, "operatorType");
           
            supportPolicyAttribute = getTextContextFromGetElementByTagName(this.myCapabilityTranslation,
                    "supportPolicyAttribute");

            concatSuppPolWithCapaValue = getTextContextFromGetElementByTagName(this.myCapabilityTranslation,
                    "concatSuppPolWithCapaValue");

            NodeList commandNameNodeList = e1.getElementsByTagName("newCommandName");
            
            //si ricavano eventuali attributi degli elementi commandName
            for (int k = 0; k < commandNameNodeList.getLength(); k++) {
                Element e2 = getElemenetIfDeferredElementImpl(commandNameNodeList.item(k));
                if (e2 == null)
                    continue;

                String commandNameStr, attributeName, attributeValue;
                HashMap<String, String> conditionCommandName = new HashMap<>();
                // si chiama la funzione che mi prende il contenuto di realCommandName e si
                // inserisce nella lista (sia che sia null sia che non lo sia)
                commandNameStr = getTextContextFromGetElementByTagName(e2, "realCommandName");

                // si chiama la funzione che mi prende il contenuto di
                // commandAttributeNameCondition e si inserice nella lista (sia che sia null
                // sia che non lo sia)
                attributeName = getTextContextFromGetElementByTagName(e2, "attributeName");

                // si chiama la funzione che mi prende il contenuto di
                // commandAttributeValueCondition e si inserice nella lista (sia che sia null
                // sia che non lo sia)

                attributeValue = getTextContextFromGetElementByTagName(e2, "attributeValue");

                if (attributeName != null)
                    conditionCommandName.put(attributeName, attributeValue);

                commandNames.add(new CommandName(commandNameStr, conditionCommandName));

            }

            // si crea la classe bodyConcatenator per rappresentare il rispettivo elemento
            BodyConcatenator bConc = new BodyConcatenator(realConcatenator, preVariable, postVariable,
                    postConcatenator, operatorType, supportPolicyAttribute,
                    concatSuppPolWithCapaValue, commandNames);

            bodyConcatenators.add(bConc);

        }

        return bodyConcatenators;
    }

    private String getPost() {
        // definito da clauseConcatenator
        String separator = " ";
        String post = getTextContextFromGetElementByTagName(this.myCapabilityTranslation, "clauseConcatenator");
        
        String nextItem = "";
        NodeList nextItemList = null;
        NodeList dependencyNodeList = this.myCapabilityTranslation.getElementsByTagName("dependency");
        for (int i = 0; i < dependencyNodeList.getLength(); i++) {
            Node DependencyNode = dependencyNodeList.item(i);
            NodeList dependencyNodeListIntern = DependencyNode.getChildNodes();
            // System.out.println(dependencyNodeListIntern.getLength());
            for (int j = 0; j < dependencyNodeListIntern.getLength(); j++) {
                // fattibile solo includendo la libreria relativa
                if (!(dependencyNodeListIntern.item(j) instanceof DeferredElementImpl)) {
                    continue;
                }
                Element conditionalElement = (Element) dependencyNodeListIntern.item(j);
                // System.out.println(conditionalElement);
                NodeList nextCapabilityList = conditionalElement.getElementsByTagName("nextCapability");
                NodeList separaList = conditionalElement.getElementsByTagName("separator");
                nextItemList = conditionalElement.getElementsByTagName("nextItem");
                for (int k = 0; k < nextCapabilityList.getLength(); k++) {
                    Element e2 = getElemenetIfDeferredElementImpl(nextCapabilityList.item(k));
                    if (e2 == null)
                        continue;
                    this.nextCapabilityTemp = e2.getTextContent();
                    // System.out.println(nextCapabilityTemp);
                }
                if (this.nextCapabilityElement != null) {
                    if (this.nextCapabilityElement.getNodeName().equalsIgnoreCase(this.nextCapabilityTemp)) {
                        for (int index = 0; index < separaList.getLength(); index++) {
                            Element e2 = getElemenetIfDeferredElementImpl(separaList.item(index));
                            if (e2 == null)
                                continue;
                            separator = e2.getTextContent();
                            // System.out.println(separator);
                        }
                    }
                }
            }
           
        }

        // si controlla se la security capability richiede la gestione della sequenza delle ultime n acl, nel caso di Squid
        if(nextItemList!=null) {
            for (int k = 0; k < nextItemList.getLength(); k++) {
                Element e2 = getElemenetIfDeferredElementImpl(nextItemList.item(k));
                if (e2 == null)
                    continue;
                nextItem = e2.getTextContent();
                // System.out.println(nextCapabilityTemp);
            }
            if(nextItem.equalsIgnoreCase("acls")) {
                separator = "";
                for(int i = aclCounter-aclRuleCounter; i<aclCounter; i++) {
                    separator = separator.concat("myacl"+i+" "); 
                }
            }
        }
        if (post != null) {
            return separator+post; // mid di default tra il pre e il body
        }
        return separator;
    }

    private String splitMultipleRule(String rule) {
        // split della regola per individuare l'insieme di parametri che devono essere
        // espansi
        String temporaryRule = rule;
        ArrayList<String> supportRule = new ArrayList<>(Arrays.asList(temporaryRule.split(" ")));

        String elementValues = null;
        Integer indexToInsert = null;
        // si cerca la stringa contenente i parametri da espandere
        for (int k = 0; k < supportRule.size(); k++) {
            if (supportRule.get(k).contains("\\p")) {
                elementValues = supportRule.get(k);
                // si rimuove la stringa contenente i parametri da trattare
                supportRule.remove(k);
                // si memorizza la posizione in cui inserire i singoli parametri in ognuna della
                // nuova regola da produrre
                indexToInsert = k;
                // quando si incontra la prima capability da espandere, si esce dal ciclo
                break;
            }
        }

        // si ottengono singolarmente i parametri da trattare
        String[] supportValues = elementValues.replace("\\p", " p ").split(" p ");

        // per ogni parametro, si crea una nuova regola (uguale alle precedenti)
        // in ogni regola cambia solo il valore del parametro in questione
        for (int k = 0; k < supportValues.length; k++) {
            supportRule.add(indexToInsert, supportValues[k]);
            if (k == 0) { // Se è il primo parametro, si sovrascrive temporaryRule con la nuova regola
                temporaryRule = String.join(" ", supportRule);
                temporaryRule = temporaryRule.concat(System.lineSeparator());
            } else {
                if (supportRule.get(0).contains(System.lineSeparator())) {
                    /**
                     * Se la prima stringa della regola contiene un lineSeparator (caso option 2 per
                     * iptables, es. *filter)
                     * si rimuove tale stringa poiché iptables vuole solo una volta il parametro di
                     * tableActionCapability
                     */
                    String[] prova = supportRule.get(0).split(System.lineSeparator());
                    supportRule.remove(0);
                    supportRule.add(0, prova[1]);
                }
                temporaryRule = temporaryRule.concat(String.join(" ", supportRule));
                if (k != supportValues.length - 1)
                    temporaryRule = temporaryRule.concat(System.lineSeparator());
            }
            // Al termine della creazione della singola regola, si rimuove il parametro
            // nella
            // posizione target
            // in modo da poter inserire il parametro successivo, nella prossima iterazione
            supportRule.remove((int) indexToInsert);
        }
        ArrayList<String> newRulesList = new ArrayList<>();
        // Se, in seguito al primo split, sono ancora presenti delle capability da
        // splittare
        // si usa la funzione splitMultipleRule in modo iterativo
        if (temporaryRule.contains("\\p")) {
            // Si prendono le singole regole
            supportRule = new ArrayList<>(Arrays.asList(temporaryRule.split("\\n")));
            for (int i = 0; i < supportRule.size(); i++) {
                // Si chiama splitMultipleRule per ognuna di esse
                String temp = splitMultipleRule(supportRule.get(i));
                newRulesList.add(temp);
            }
        }

        if (newRulesList.size() != 0) {
            temporaryRule = String.join(System.lineSeparator(), newRulesList);
        }

        return temporaryRule;
    }

    // funziona che verifica se le regole delle dipendenza sono soddisfatte
    private boolean checkRule() {
        
        // per ogni capability che ho nella regola
        for (int i = 0; i < this.temporaryListCapabilityOfRule.size(); i++) {
            // devono essere TUTTE rispettate le dipendenze delle capability
            boolean found = true;

            // System.out.println(this.temporaryListCapabilityOfRule.get(i));
            // si mette la capability in temporary security capability perché
            // findElementoTranslationNodesByCapability lavora con quella security
            // capability
            this.temporaryCapability = this.temporaryListCapabilityOfRule.get(i);
            // System.out.println(this.temporaryCapability);
            if (this.temporaryCapability.equals("label"))
                return found;

            // si cerca l'adapter della capability
            this.myCapabilityTranslation = findElementoTranslationNodesByCapability();

            // System.out.println("analizzo la capa: "+this.temporaryCapability);
            if (this.myCapabilityTranslation == null) {
                System.out.println("[Rule #" + ruleId + "]" + " ERROR: " + this.temporaryCapability
                        + " capabilityTranslationDetails not available.");
                return false;
            }

            // si cercano le dependency
            NodeList dependencyNodeList = this.myCapabilityTranslation.getElementsByTagName("dependency");

            // List<String> respectedDependencyOfCapa = new ArrayList<String>();

            for (int j = 0; j < dependencyNodeList.getLength(); j++) {
                // per ogni capability si controlla se ALMENO UNA delle dipendenze in or è
                // verificata
                List<String> presenceOfCapability = new ArrayList<String>(), presenceOfValue = new ArrayList<String>(),
                        absenceOfCapability = new ArrayList<String>(), absenceOfValue = new ArrayList<String>();
                found = true;
                Element e1 = getElemenetIfDeferredElementImpl(dependencyNodeList.item(j));
                if (e1 == null)
                    continue;

                // si genera la lista di stringhe relative ai rispettivi elementi
                presenceOfCapability = getListOfTextValueOfElementByTagNameFromElement(e1, "presenceOfCapability");
                presenceOfValue = getListOfTextValueOfElementByTagNameFromElement(e1, "presenceOfValue");
                absenceOfCapability = getListOfTextValueOfElementByTagNameFromElement(e1, "absenceOfCapability");
                absenceOfValue = getListOfTextValueOfElementByTagNameFromElement(e1, "absenceOfValue");
                /**
                 * for(int k = 0; k < presenceOfCapability.size(); k++) {
                 * if(!presenceOfCapability.isEmpty())
                 * System.out.println("presenceOfCapability nella lista "
                 * +presenceOfCapability.get(k)); } for(int k = 0; k < presenceOfValue.size();
                 * k++) { if(!presenceOfValue.isEmpty())
                 * System.out.println("presenceOfValue nella lista " +presenceOfValue.get(k)); }
                 * for(int k = 0; k < absenceOfCapability.size(); k++) {
                 * if(!absenceOfCapability.isEmpty())
                 * System.out.println("absenceOfCapability nella lista "
                 * +absenceOfCapability.get(k)); } for(int k = 0; k < absenceOfValue.size();
                 * k++) { if(!absenceOfValue.isEmpty())
                 * System.out.println("absenceOfValue nella lista " +absenceOfValue.get(k)); }
                 */

                // per ogni capability per cui c'è una dipendenza
                for (int k = 0; k < presenceOfCapability.size(); k++) {
                    if (presenceOfCapability.get(k) == null)
                        continue;
                    boolean found2 = false;
                    // si controlla se è presente in tutte le capability della regola
                    for (int h = 0; h < this.temporaryListCapabilityOfRule.size(); h++) {
                        // se la trovo
                        if (presenceOfCapability.get(k).equalsIgnoreCase(this.temporaryListCapabilityOfRule.get(h))) {
                            found2 = true;
                        }
                    }
                    // se si termina il controllo senza trovare la dipendenza
                    // found rimane a false e quindi si conclude che la regola non
                    // è rispettata
                    if (!found2) {
                        // System.out.println("[Rule #" + ruleId + "]" + " ERROR: One or more of the following Security Capability is missing: "+String.join(", ", presenceOfCapability)+".");
                        found = false;
                    }
                }
                // per ogni valore per cui c'è una dipendenza
                for (int k = 0; k < presenceOfValue.size(); k++) {
                    if (presenceOfValue.get(k) == null)
                        continue;
                    if (!this.temporaryRule.contains(presenceOfValue.get(k))) { // se non è contenuta
                        // System.out.println("[Rule #" + ruleId + "]" + " ERROR: One or more of the following values is missing: "+String.join(", ", presenceOfValue)+".");
                        found = false; // si pone found a false;
                    }
                }
                for (int k = 0; k < absenceOfCapability.size(); k++) { // per ogni capability per cui c'è una dipendenza
                    if (absenceOfCapability.get(k) == null)
                        continue;
                    boolean found2 = false;
                    // si controlla se è presente in tutte le capability della regola
                    for (int h = 0; h < this.temporaryListCapabilityOfRule.size() && h<absenceOfCapability.size(); h++) {
                        if (absenceOfCapability.get(h).contentEquals(this.temporaryListCapabilityOfRule.get(h))) { // se
                                                                                                                   // è
                                                                                                                   // contenute
                            found2 = true; // male
                        }
                    }
                    // se si termina il controllo senza trovare la dipendenza
                    // found rimane a false e quindi si conclude che la regola non
                    // è rispettata
                    if (found2) {
                        // System.out.println("[Rule #" + ruleId + "]" + " ERROR: One or more of the following forbidden SecurityCapability is present: "+String.join(", ", absenceOfCapability)+".");
                        found = false;
                    }
                }
                // per ogni valore per cui c'è una dipendenza
                for (int k = 0; k < absenceOfValue.size(); k++) {
                    if (absenceOfValue.get(k) == null)
                        continue;
                    if (this.temporaryRule.contains(absenceOfValue.get(k))) {// se non è contenuta
                        // System.out.println("[Rule #" + ruleId + "]" + " ERROR: One or more of the following forbidden value is present: "+String.join(", ", absenceOfCapability)+".");
                        found = false; // si pone found a falso
                    }
                }

                if (found) { // se si trova un true vuol dire che c'è un insieme dipendenze soddisfatte
                    // System.out.println("ho trovato le dipendenze rispettate!!!");
                    break;
                }
            }
            // se una security capability non rispetta le dipendenze allora return false
            if (!found)
                return false;
        }

        return true;
    }

    // funzione che ritorna una lista contenente tutti i valori testuali contenuti
    // negli elementi figlio dell'elemento passato
    private List<String> getListOfTextValueOfElementByTagNameFromElement(Element e, String tagName) {
        List<String> ls = new ArrayList<String>();

        NodeList nl = e.getElementsByTagName(tagName);
        for (int k = 0; k < nl.getLength(); k++) {
            Element e2 = getElemenetIfDeferredElementImpl(nl.item(k));
            if (e2 == null)
                continue;
            // System.out.println(tagName+" "+e2.getTextContent());
            ls.add(e2.getTextContent());
        }

        return ls;
    }

    private String getDefaultActionRule(NodeList defaultActionList, String destinationNSF) {
        /**
         * Gestione defaultAction: sostanzialmente si usa
         * lo stesso codice per la traduzione di una rule generica
         */
        String startTemporaryRule = this.temporaryRule; 
        for (int j = 0; j < defaultActionList.getLength(); j++) {
            Node defaultAction = defaultActionList.item(j);
            if (!(defaultAction instanceof DeferredElementImpl)) { // fattibile solo includendo la libreria relativa
                continue;
            }
            NodeList defaultActionElements = defaultAction.getChildNodes();
            this.temporaryCapabilityAndAttributes = "";

            if(nsfName.equalsIgnoreCase("IpTables")) {
                exploreElement((Element) defaultAction);
                String ret = clauseConverter(destinationNSF);
                if (ret != null) {
                    // se ho tradotto in qualcosa di utile allora lo aggiungo alla regola
                    this.temporaryRule = this.temporaryRule + ret;
                    this.temporaryListCapabilityOfRule.add(this.temporaryCapability);
                }
                this.temporaryCapabilityAndAttributes = "";
            }
            for (int k = 0; k < defaultActionElements.getLength(); k++) { // ciclo sulle capability all'interno della rule selezionata
                if (!(defaultActionElements.item(k) instanceof DeferredElementImpl)) { // fattibile solo includendo la libreria relativa
                    continue;
                }
                Element capability = (Element) defaultActionElements.item(k);

                List<String> supportedConditionOperator = getEnumerationLiterals("SupportedConditionOperatorEnumeration"); 
                List<String> supportedActionOperator = getEnumerationLiterals("SupportedActionOperatorEnumeration"); 
                // Si ottiene il valore di operator per la security capability in questione
                if (capability.getAttribute("operator") != "") {
                    // si differenzia l'utilizzo dell'operatore in base al tipo della capability
                    if(capability.getNodeName().contains("Condition")) {
                        if(supportedConditionOperator.contains(capability.getAttribute("operator"))) {
                            requestedConditionOperator = capability.getAttribute("operator");
                        } else {
                            System.out.println("[Rule #" + ruleId + "]" + " ERROR: " + capability.getNodeName()
                                        + " tried to use an operator not supported for Condition Capabilities.");
                            this.temporaryRule = ""; 
                            break;
                        }
                    } else if(capability.getNodeName().contains("Action")) {
                        capabilityType = "Action";
                        if(supportedActionOperator.contains(capability.getAttribute("operator"))) {
                            requestedActionOperator = capability.getAttribute("operator");
                        } else {
                            System.out.println("[Rule #" + ruleId + "]" + " ERROR: " + capability.getNodeName()
                                        + " tried to use an operator not supported for Action Capabilities.");
                            this.temporaryRule = ""; 
                            break;
                        }
                    }
                }
                if(capability.getNodeName().contains("Condition"))
                    capabilityType = "Condition";
                else 
                    capabilityType = "Action";
                exploreElement(capability);

                String ret = clauseConverter(destinationNSF);
                if (ret != null) {
                    // se ho tradotto in qualcosa di utile allora lo aggiungo alla regola
                    this.temporaryRule = this.temporaryRule + ret;
                    this.temporaryListCapabilityOfRule.add(this.temporaryCapability);
                }
                this.temporaryCapabilityAndAttributes = "";
            }
        }

        if(startTemporaryRule.equals(this.temporaryRule))
            this.temporaryRule = null;
        return this.temporaryRule;
    }

    // Funzione per ricevere l'id della security Capability riferita
    /**
     * private String idSecurityCapability(Element item){
     * if(!item.getAttribute("id").equalsIgnoreCase("")){ return
     * item.getAttribute("id"); } return null; }
     */

    // stampa nella stringa di riferimento l'elemento che viene passato. vengono
    // stampati il tipo di capability che si sta considerando e gli attributi
    /**
     * private void stampa(Element e) { for(int i=0; i < this.lenght; i++){
     * 
     * } if(e.getAttribute("xsi:type")!="") {
     * //System.out.println(e.getAttribute("xsi:type"));
     * this.temporaryCapabilityAndAttributes =
     * this.temporaryCapabilityAndAttributes.concat(e.getAttribute("xsi:type")+" ");
     * }else if(e.getChildNodes().getLength()==1) {
     * //System.out.println("\t"+e.getNodeName());
     * this.temporaryCapabilityAndAttributes =
     * this.temporaryCapabilityAndAttributes.concat(e.getNodeName()+" ");
     * this.temporaryCapabilityAndAttributes =
     * this.temporaryCapabilityAndAttributes.concat(e.getTextContent()+" "); } }
     */

    private ArrayList<String> fromUnionToExactMatch(String[] s) {

        BodyConcatenator innerBodyConcat = null;
        ArrayList<String> newValues = new ArrayList<>();
        System.out.println("[Rule #" + ruleId + "]" + " WARNING: Union operator for " + s[0]
                + " is not available. Union expanded using exactMatch operator.");

        // ottengo gli elementValue
        for (int j = 0; j < s.length; j++) {
            // poiché non supportato, non è noto un bodyConcatenator per il rispettivo
            // operatore

            // è necessario individuare il tipo di elementi della union: elementValue o
            // elementRange (nodi: range,start,end)
            if (s[j].equals("elementValue")) {
                // se è elementValue, non è necessario individuare alcun concatenator interno
                newValues.add(validateParameter(s[j], s[j + 1]));
                // il carattere \p è usato per indicare che è una regola da espandere in regole
                // multiple
                // visto che l'unico operatore supportato è exactMatch (aka un solo parametro
                // per la capability)
                newValues.add("\\p");
            } else if (s[j].equals("elementRange")) {
                // se è elementRange, devo gestire il tipo di range utilizzato nell'unione
                // si suppone che l'operatore interno sia supportato
                innerBodyConcat = getRequiredBodyConcat(bodyConcatenators, s[j + 1]);
                if (innerBodyConcat != null) {
                    String parameterA, parameterB, concatenator;
                    // si prende un substring della regola poiché è necessario considerare i
                    // parametri successivi all'indice j
                    // in questo modo, indexOf funziona considerando il primo parametro utile dopo
                    // l'indice j e non solo il primo dell'ArrayList
                    ArrayList<String> supportRule = new ArrayList<>(Arrays.asList(s).subList(j, s.length));
                    // si estrae il primo parametro considerando l'elemento successivo all'elemento
                    // preVariable (postVariable) dell'innerBodyConcat individuato
                    parameterA = supportRule.get(supportRule.indexOf(innerBodyConcat.preVariable) + 1);
                    parameterB = supportRule.get(supportRule.indexOf(innerBodyConcat.postVariable) + 1);
                    concatenator = innerBodyConcat.realConcatenator;
                    newValues.add(validateParameter(innerBodyConcat.preVariable, parameterA) +
                            concatenator +
                            validateParameter(innerBodyConcat.postVariable, parameterB));
                    newValues.add("\\p");

                } else {
                    /**
                     * Potrebbe dare problemi in futuro!
                     * Come nel caso in cui non è richiesto un operatore:
                     * L'operazione di espansione non è supportata per gli operatori interni
                     *
                     * supporto all'espansione range->exactMatch nel caso di securityCapability
                     * generiche con parametri di tipo intero
                     * dato che per questo tipo di parametri non è supportato nessun operatore se
                     * non exactMatch si procede come segue:
                     * caso: union(range,element,range)
                     * union espanso verso exactMatch
                     * durante l'espansione il range di interi si espande verso exactMatch
                     * nota: ciò è fatto solo per interi poiché range->exactMatch per gli IP può
                     * essere lunga e dispendiosa
                     */
                    if (regexValidity(s[j + 3], "^([0-9]|[1-9][0-9]*)$")) {
                        System.out.println("[Rule #" + ruleId + "]"
                                + " WARNING: Only in this case, inner operator (type integer) is expanded toward a supported one.");
                        ArrayList<String> rangeToExactList = fromRangeToExactMatch(Arrays.copyOfRange(s, j, s.length));
                        newValues.addAll(rangeToExactList);
                    } else {
                        System.out.println(
                                "[Rule #" + ruleId + "]" + " ERROR: Cannot translate inner operator in " + s[0] + ".");
                        return null;
                    }

                }

            } else if (s[j].equals("elementEncryption")) {
                innerBodyConcat = getRequiredBodyConcat(bodyConcatenators, "exactMatch");
                ArrayList<String> supportRule = new ArrayList<>(Arrays.asList(s).subList(j, s.length));
                Integer indexParameterA = supportRule.indexOf(innerBodyConcat.preVariable)+1; 
                Integer indexParameterB = supportRule.indexOf(innerBodyConcat.postVariable)+1; 

                newValues.add(validateParameter(innerBodyConcat.preVariable,supportRule.get(indexParameterA))+
                                                innerBodyConcat.realConcatenator+
                              validateParameter(innerBodyConcat.postVariable,supportRule.get(indexParameterB)));
                newValues.add("\\p");
            }

        }

        if (newValues.size() == 0)
            return null;
        else
            return newValues;

    }

    private ArrayList<String> fromRangeToExactMatch(String[] s) {

        ArrayList<String> newValues = new ArrayList<>();
        String start = null, end = null;
        System.out.println("[Rule #" + ruleId + "]" + " WARNING: Range operator for " + s[0]
                + " is not available. Range expanded using exactMatch operator.");

        // per ogni tipo di range preVariable e postVariable sono sempre start e end
        // si ottengono i valori dei parametri start and end
        for (int j = 0; j < s.length; j++) {

            // si assume che i valori dei parametri siano successivi a start e end
            if (s[j].equals("start")) { // se è un valore del parametro, lo valido con validateParameter
                start = validateParameter(s[j], s[j + 1]);

            } else if (s[j].equals("end")) {
                end = validateParameter(s[j], s[j + 1]);

            }

        }
        // si itera da start a end, intervallandoli dal carattere \p per indicare
        // che è una regola da espandere in regole multiple
        if (start != null && end != null) {
            // l'espansione avviene diversamente in base a se il tipo del valore del
            // parametro è: int, ip o plainString
            if (isTypeInteger("start")) {
                for (Integer singleValue = Integer.parseInt(start); singleValue <= Integer
                        .parseInt(end); singleValue++) {
                    newValues.add(singleValue.toString());
                    newValues.add("\\p");
                }
            } else if (isTypeIp("start")) {
                IPAddressString startAddressString = new IPAddressString(start);
                IPAddress startAddress = startAddressString.getAddress();
                Long intStartAddresS = startAddress.getValue().longValue();

                // si ottiene il valore decimale dell'indirizzo IP end
                IPAddressString endAddressString = new IPAddressString(end);
                IPAddress endAddress = endAddressString.getAddress();
                Long intEndAddress = endAddress.getValue().longValue();

                // si iterano gli indirizzi ip dal primo all'ultimo (in decimale)
                for (Long j = intStartAddresS; j <= intEndAddress; j++) {

                    // si ottiene l'indirizzo IP in forma dotted decimal dal valore decimale
                    IPAddress newIpAddress = new IPv4Address(j.intValue());
                    newValues.add(newIpAddress.toString());
                    newValues.add("\\p");

                }
            }
        } else {
            return null;
        }

        return newValues;

    }

    /**
     * Potrebbe dare problemi in futuro!
     * Le seguenti funzioni di tipo isType* sono utilizzate per rendere generici
     * i metodi di espansione. Interi, indirizzi IP e stringhe saranno trattati in
     * modo diverso
     * 
     * Dalla regex del parametro viene usato un generatore che produrrà una stringa
     * random che rispetta tale regex
     * Per isTypeInteger si prova a parsarla come Integer, per isTypeIp si controlla
     * se la stringa contiene un punto
     * per isTypePlainString si controlla se la striga NON contenga un punto.
     * 
     * 
     */
    private Boolean isTypeInteger(String parameterName) {
        Boolean isInt = true;

        if (attributeRegexMap.containsKey(parameterName)) {
            String regex = attributeRegexMap.get(parameterName);
            Generex generex = new Generex(regex.replace("$", "").replace("^", ""));
            String randomStr = generex.random();
            try {
                Integer i = Integer.parseInt(randomStr);
            } catch (NumberFormatException nfe) {
                isInt = false;
            }
        }
        return isInt;
    }

    private Boolean isTypeIp(String parameterName) {
        Boolean isIp = true;

        if (attributeRegexMap.containsKey(parameterName)) {
            String regex = attributeRegexMap.get(parameterName);
            Generex generex = new Generex(regex.replace("$", "").replace("^", ""));
            String randomStr = generex.random();
            if (!randomStr.contains(".")) {
                isIp = false;
            }
        }
        return isIp;
    }

    private Boolean isTypePlainString(String parameterName) {
        Boolean isPlainString = true;

        if (attributeRegexMap.containsKey(parameterName)) {
            String regex = attributeRegexMap.get(parameterName);
            Generex generex = new Generex(regex.replace("$", "").replace("^", ""));
            String randomStr = generex.random();
            if (randomStr.contains(".")) {
                isPlainString = false;
            }
        }
        return isPlainString;
    }

    private ArrayList<String> fromRangeToUnion(String[] s) {

        ArrayList<String> newValues = new ArrayList<>();
        String start = null, end = null;
        System.out.println(
                "[Rule #" + ruleId + "]" + " WARNING: Range operator for " + s[0]
                        + " is not available. Range expanded using Union operator.");

        // per ogni tipo di range preVariable e postVariable sono sempre start e end
        // si ottiene i valori dei parametri start and end
        for (int j = 0; j < s.length; j++) {

            // si assume che i valori dei parametri siano successivi a start e end
            if (s[j].equals("start")) { // se è un valore del parametro, lo si valida con validateParameter
                start = validateParameter(s[j], s[j + 1]);

            } else if (s[j].equals("end")) {
                end = validateParameter(s[j], s[j + 1]);

            }

        }
        // si itera da start a end, intervallandoli dal carattere \p per indicare
        // che è una regola da espandere in regole multiple
        if (start != null && end != null) {
            // l'espansione avviene diversamente in base a se il tipo del valore del
            // parametro è: int, ip o plainString
            if (isTypeInteger("start")) {
                for (Integer singleValue = Integer.parseInt(start); singleValue <= Integer
                        .parseInt(end); singleValue++) {
                    newValues.add(singleValue.toString());
                }
            }

            if (isTypeIp("start")) {
                IPAddressString startAddressString = new IPAddressString(start);
                IPAddress startAddress = startAddressString.getAddress();
                Long intStartAddresS = startAddress.getValue().longValue();

                // ottengo il valore decimale dell'indirizzo IP end
                IPAddressString endAddressString = new IPAddressString(end);
                IPAddress endAddress = endAddressString.getAddress();
                Long intEndAddress = endAddress.getValue().longValue();

                // itero gli indirizzi ip dal primo all'ultimo (in decimale)
                for (Long j = intStartAddresS; j <= intEndAddress; j++) {

                    // ottengo l'indirizzo IP in forma dotted decimal dal valore decimale
                    IPAddress newIpAddress = new IPv4Address(j.intValue());
                    newValues.add(newIpAddress.toString());

                }
            }
        } else {
            return null;
        }
        return newValues;
    }

    // TODO: fromRangeMaskToExactMatch
    // private ArrayList<String> fromRangeMaskToExactMatch(String[] s) {
    // }

    // TODO: fromRangeMaskToUnion
    // private ArrayList<String> fromRangeMaskToUnion(String[] s) {
    // }

    private ArrayList<String> fromRangeMaskToRange(String[] s) {

        // List<String> supportRule = Arrays.asList(s);
        ArrayList<String> newValues = new ArrayList<>();
        String address = null, mask = null;
        System.out.println("[Rule #" + ruleId + "]" + " WARNING: RangeMask operator for " + s[0]
                + " is not available. RangeMask expanded using Range operator.");

        for (int j = 0; j < s.length; j++) {
            // si assume che i parametri per gli indirizzi siano gli elementi in seguito a
            // address e mask
            if (s[j].equals("address")) { // se è un valore del parametro, lo valido con validateParameter
                address = validateParameter(s[j], s[j + 1]);

            } else if (s[j].equals("mask")) {
                mask = validateParameter(s[j], s[j + 1]);

            }
        }
        if (address != null && mask != null) {
            // si ottiene il primo indirizzo della subnet
            String startAddress = fixNetAddress(address, mask);
            // si compone l'indirizzo subnet/netmask
            IPAddressString addrString = new IPAddressString(startAddress + "/" + mask);
            IPAddress addr = addrString.getAddress();
            // IPAddressSegment rappresentano i valori possibili che ogni segmento può
            // assumere, es:{192-194, 0-255, 0-255, 0-13}
            IPAddressSegment[] segments = addr.getSegments();
            String endAddress = "";
            // !!!--- iptables accetta come startAddress il primo indirizzo della subnet
            // se l'indirizzo fornito nella regola appartiene alla subnet, si usa tale
            // indirizzo come startAddress
            // altrimenti si usa il primo indirizzo della rete
            // if(addr.contains(new IPAddressString(address).getAddress()))
            // {
            // startAddress = address;
            // }
            for (IPAddressSegment seg : segments) {
                if (seg.getWildcardString().contains("-"))
                    endAddress += "." + seg.getWildcardString().split("-")[1];
                else if (seg.getWildcardString().contains("*"))
                    endAddress += ".255";
                else
                    endAddress += "." + seg.getString();
            }
            // in base ai range che i segmenti possono assumere, compongo l'endAddress
            endAddress = endAddress.substring(1);
            newValues.add(startAddress);
            newValues.add(endAddress);

        } else {
            return null;
        }

        return newValues;

    }

    private ArrayList<String> fromRangeMaskToRangeCIDR(String[] s) {
        // List<String> supportRule = Arrays.asList(s);
        ArrayList<String> newValues = new ArrayList<>();
        String address = null, mask = null;
        System.out.println("[Rule #" + ruleId + "]" + " WARNING: RangeMask operator for " + s[0]
                + " is not available. RangeMask expanded using RangeCIDR operator.");

        for (int j = 0; j < s.length; j++) {
            // si assume che i parametri per gli indirizzi siano gli elementi in seguito a
            // address e mask
            if (s[j].equals("address")) { // se è un valore del parametro, lo valido con validateParameter
                address = validateParameter(s[j], s[j + 1]);

            } else if (s[j].equals("mask")) {
                mask = validateParameter(s[j], s[j + 1]);

            }
        }
        if (address != null && mask != null) {
            // si ottiene il primo indirizzo della subnet
            String startAddress = fixNetAddress(address, mask);
            // si compone l'indirizzo subnet/netmask
            IPAddressString addrString = new IPAddressString(startAddress + "/" + mask);
            IPAddress addr = addrString.getAddress();
            // IPAddress è una classe che rappresenta l'IP in formato ipAddress/maskCIDR
            String maskCIDR = addr.toString().split("/")[1];
            // !!!--- iptables accetta come startAddress il primo indirizzo della subnet
            // se l'indirizzo fornito nella regola appartiene alla subnet, si usa tale
            // indirizzo come startAddress
            // altrimenti si usa il primo indirizzo della rete
            // if(addr.contains(new IPAddressString(address).getAddress()))
            // {
            // startAddress = address;
            // }

            newValues.add(startAddress);
            newValues.add(maskCIDR);

        } else {
            return null;
        }

        return newValues;

    }

    private String fixNetAddress(String address, String mask) {

        String addressBinary = getBinaryIpFormat(address);
        String maskBinary = getBinaryIpFormat(mask);
        String newAddress = "";
        for (int i = 0; i < maskBinary.length(); i++) {
            if (maskBinary.charAt(i) == '1') {
                newAddress += addressBinary.charAt(i);
            }
            if (maskBinary.charAt(i) == '0') {
                newAddress += '0';
            }
        }

        return binaryIpToCanonical(newAddress);
    }

    // funzione che ritorna la notazione binaria di un indirizzo ip fornito in forma
    // dotted decimal
    private String getBinaryIpFormat(String ipAddress) {
        IPAddressString addressString = new IPAddressString(ipAddress);
        IPAddress address = addressString.getAddress();
        String binaryString = address.toBinaryString();
        return binaryString;

    }

    // TODO: fromRangeCIDRToExactMatch
    // private ArrayList<String> fromRangeCIDRToExactMatch(String[] s) {
    // }

    // TODO: fromRangeCIDRToUnion
    // private ArrayList<String> fromRangeCIDRToUnion(String[] s) {
    // }

    private ArrayList<String> fromRangeCIDRToRange(String[] s) {

        // List<String> supportRule = Arrays.asList(s);
        ArrayList<String> newValues = new ArrayList<>();
        String address = null, mask = null;
        System.out.println("[Rule #" + ruleId + "]" + " WARNING: RangeCIDR operator for " + s[0]
                + " is not available. RangeCIDR expanded using Range operator.");

        for (int j = 0; j < s.length; j++) {

            // si assume che i parametri per gli indirizzi siano gli elementi in seguito a
            // address e maskCIDR
            if (s[j].equals("address")) { // se è un valore del parametro, lo valido con validateParameter
                address = validateParameter(s[j], s[j + 1]);

            } else if (s[j].equals("maskCIDR")) {
                mask = validateParameter(s[j], s[j + 1]);

            }
        }
        if (address != null && mask != null) {
            // si ottiene il primo indirizzo della subnet
            String startAddress = fixNetAddressCIDR(address, mask);
            // si compone l'indirizzo subnet/maskCIDR
            IPAddressString addrString = new IPAddressString(startAddress + "/" + mask);
            IPAddress addr = addrString.getAddress();
            // si ottiene il valore della subnet mask
            IPAddressSegment[] segments = addr.getSegments();
            String endAddress = "";
            // !!!--- iptables accetta come startAddress il primo indirizzo della subnet
            // se l'indirizzo fornito nella regola appartiene alla subnet, si usa tale
            // indirizzo come startAddress
            // altrimenti si usa il primo indirizzo della rete
            // if(addr.contains(new IPAddressString(address).getAddress()))
            // {
            // startAddress = address;
            // }
            for (IPAddressSegment seg : segments) {
                if (seg.getWildcardString().contains("-"))
                    endAddress += "." + seg.getWildcardString().split("-")[1];
                else if (seg.getWildcardString().contains("*"))
                    endAddress += ".255";
                else
                    endAddress += "." + seg.getString();
            }
            // in base ai range che i segmenti possono assumere, compongo l'endAddress
            endAddress = endAddress.substring(1);
            newValues.add(startAddress);
            newValues.add(endAddress);

        } else {
            return null;
        }

        return newValues;

    }

    private ArrayList<String> fromRangeCIDRToRangeMask(String[] s) {

        // List<String> supportRule = Arrays.asList(s);
        ArrayList<String> newValues = new ArrayList<>();
        String address = null, mask = null;
        System.out.println("[Rule #" + ruleId + "]" + " WARNING: RangeCIDR operator for " + s[0]
                + " is not available. RangeCIDR expanded using RangeMask operator.");

        for (int j = 0; j < s.length; j++) {

            // si assume che i parametri per gli indirizzi siano gli elementi in seguito a
            // address e maskCIDR
            if (s[j].equals("address")) { // se è un valore del parametro, lo valido con validateParameter
                address = validateParameter(s[j], s[j + 1]);

            } else if (s[j].equals("maskCIDR")) {
                mask = validateParameter(s[j], s[j + 1]);

            }
        }
        if (address != null && mask != null) {
            // si ottiene il primo indirizzo della subnet
            String startAddress = fixNetAddressCIDR(address, mask);
            // si compone l'indirizzo subnet/maskCIDR
            IPAddressString addrString = new IPAddressString(startAddress + "/" + mask);
            IPAddress addr = addrString.getAddress();
            // si ottiene il valore della subnet mask
            String subnetString = addr.getNetworkMask().toString().split("/")[0];

            // se l'indirizzo fornito nella regola appartiene alla subnet, si usa tale
            // indirizzo come address
            // altrimenti si usa il primo indirizzo della rete
            // if(addr.contains(new IPAddressString(address).getAddress()))
            // {
            // startAddress = address;
            // }

            newValues.add(startAddress);

            newValues.add(subnetString);

        } else {
            return null;
        }

        return newValues;

    }

    private String fixNetAddressCIDR(String address, String mask) {

        String addressBinary = getBinaryIpFormat(address);
        String newAddress = "";
        for (int i = 0; i < addressBinary.length(); i++) {
            if (i < Integer.parseInt(mask)) {
                newAddress += addressBinary.charAt(i);
            } else {
                newAddress += '0';
            }
        }
        return binaryIpToCanonical(newAddress);
    }

    // funzione che ritorna la notazione in forma dotted decimal di un indirizzo ip
    // fornito in forma binaria
    private String binaryIpToCanonical(String binaryIpAddress) {

        // IPAddressString richiede la forma binaria del tipo
        // 0b01010110.0b11101001.0b10000001.0b10000111
        ArrayList<String> newBinaryList = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            newBinaryList.add("0b" + binaryIpAddress.substring(i * 8, i * 8 + 8) + ".");
        }
        String newBinary = String.join("", newBinaryList);
        newBinary = newBinary.substring(0, newBinary.length() - 1);

        IPAddressString supporAddressString = new IPAddressString(newBinary);
        IPAddress supportIpAddress = supporAddressString.getAddress();
        return supportIpAddress.toString();

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

    private Object executeDynamicMethod(String methodName, Object inputParameter) {

        try {

            Method methodToCall = null; 
            if(inputParameter instanceof String)
                methodToCall = NSFTranslator.class.getDeclaredMethod(methodName,
                java.lang.String.class);
            else if (inputParameter instanceof String[])
            // si ottiene il metodo desiderato della classe NSFTranslator
            methodToCall = NSFTranslator.class.getDeclaredMethod(methodName,
                    java.lang.String[].class);

            // chiamata del metodo
            Object ret = methodToCall.invoke(it, (Object) inputParameter);

            return ret; 
        
        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException ex) {
            /**
             * Potrebbe dare problemi in futuro!
             * se si incontra una eccezione di tipo NoSuchMethodException allora si assume
             * che
             * il metodo astratto non è implementato
             */
            System.out.print("[Rule #" + ruleId + "]" + " ERROR: " + ex.getClass().getSimpleName()
                    + " encountered after calling abstract method.");

            return null;
        }
    }

    private Boolean isRegex(String checkString) {
        // poiché tutte le stringhe sono valide come regex, non è possibile utilizzare un metodo di verifica più intelligente
        if(checkString.contains("?")||checkString.contains("*")||checkString.contains("+")||checkString.contains("^")||checkString.contains("$")) //se è una regex, non si fa nulla
            return true;
        else 
            return false; 
            

    }
}