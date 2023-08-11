# security-capability-model

Web service that provides the access to various tool oriented to Medium Level Language generation and Low Level Policy Translation. 

From the web service home page, it is possible to clear folders reserved for each tool. Also, it is possible to navigate across the offered tools. 

The web service provides access to

* Converter: page that makes the user upload a Security Capability Model in XMI format that will be converted in XSD format. 
* Language Generator: page that makes the user upload a NSFCatalogue storing the available NSFs and the owned Security Capabilities. It allows the creation of the Abstract Language (Medium Level Language) for a selected NSF. 
* Translator: page that makes the user upload a Rule Instance expressed using NSF Abstract Language and that translates the Rule Instance items into Low Level Policies, based on NSF low level language. 

# Getting Started
## Prerequisites
In order to run the proposed framework, Docker is required and it can be found [here](https://docs.docker.com/get-docker/). 
 
## Installation
Clone the current repository: <br>
`git clone git@github.com:torsec/security-capability-model.git`

Move into project folder: <br>
`cd security-capability-model`

Move into enforcer folder: <br>
`cd enforcer`

Build Dockerfile: <br>
`docker build -t enforcer .`

Run the Dockerfile containing the proposed enforcer: <br>
`docker run -p 8080:5000 enforcer`

At this point, the enforcer is listening on `http://localhost:8080`.

## Usage

<a name="webgui"></a>
### Enforcer GUI 

It is possible to use the Enforcer directly from its GUI using the required files stored in `src/` directory. 

Converter page lets the user to upload a Capability Data Model in xmi format (usually extracted from Modelio modeling software), then it is possible to generate the Model in xsd format. 

Language Generator page lets the user to upload the NSF Catalogue, select an NSF among the availables and then generate the correspondent abstract language. 

Translator page lets the user upload a Rule Instance file and then translate it into low level language policies. The Enforcer will automaticcaly check for available abstract language for the NSF name stated within the uploaded Rule Instance. 

### Enforcer Test Files 
Under `enforcerTests/` three Python test scripts are available. They perform the required `requests` that embody the steps described in [Enforcer GUI](#webgui). <br>
In order to execute them, it is needed that the above enforcer Docker is running. From `enforcerTests/` folder: <br>
* `python3 -m venv ./venv` to create the Python venv. 
* `source venv/bin/activate` to activate the Python venv.
* `pip install -r requirements.txt` to install Python requirements.
* `python testConverter.py` to upload the Model in xmi and to convert it in xsd format. 
* `python testLanguage.py [nsfName]` to upload the most recent NSF Catalogue and generate abstract language for `nsfName`. If `nsfName` is omitted, the enforcer will generate the Abstract Language for all the available NSFs.
* `python testTranslator.py rule/instance/path [destinationNSF]` to upload a desired Rule Instance providing its path and to translate it to low level policies. For generic NSFs it is possible to set the `destinationNSF` toward which the translation has to be performed. 

### Java JAR

The above usage methods require to have the enforcer Docker running. An alternative could be to directly execute the tools through java command line interface. 
Starting from `/src` folder. <br>
* Upload Capability Data Model xmi and convert it into xsd format: <br>
`cd newConverter` <br>
`java -jar newConverter.jar definitivo.xmi`

* Upload NSF Catalogue and generate abstract language for `nsfName`:<br>
`cd ../newLanguage` <br>
`java -jar newLanguage.jar ../newConverter/capability_data_model.xsd ./NSFCatalogue.xml nsfName NSFlanguages/`

* Upload Rule Instance and translate it into low level policies:<br>
`cd ../newTranslator` <br>
`java -jar newTranslator.jar ../newLanguage/NSFLanguages/language_nsfName.xsd ../newLanguage/NSFCatalogue.xml ./RuleInstances/nsfName_RuleInstance.xml LowLevelPolicies/`
