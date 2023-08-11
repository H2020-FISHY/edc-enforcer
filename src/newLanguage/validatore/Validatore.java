package validatore;

import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.File;
import java.io.IOException;

public class Validatore {
	String xsd, xml;

	public Validatore(String xsd, String xml) {
        //System.out.println(xsd+" "+xml);
		this.xsd = xsd;
		this.xml = xml;
	}
	
    public boolean validate() {
        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        
        try {
            //Schema schema = schemaFactory.newSchema(new File("xsd/CapabilityDataModel.BaseCapability.xsd"));
        	Schema schema = schemaFactory.newSchema(new File(this.xsd));

            Validator validator = schema.newValidator();
            //validator.validate(new StreamSource(new File("xml/5-tuple.xml")));
            validator.validate(new StreamSource(new File(this.xml)));
            return true;
        } catch (SAXException | IOException e) {
            System.out.println("Error: " + e.getMessage());
            return false;
        }
    }
    
}
