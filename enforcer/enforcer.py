import os
import sys
import subprocess
import requests
import threading
from flask import Flask, flash, request, redirect, url_for, render_template, send_from_directory, session
import xml.etree.ElementTree as ET
from rabbit_consumer import RMQsubscriber

UPLOAD_FOLDER = 'uploads/'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

def allowed_file(filename, allowed_extensions):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

def searchFileName(path, ext):
    for root, dirs, files in os.walk(path):
        for file in files:
            if(ext.lower() in file.lower()):
                return file

def make_tree(path):
    tree = dict(name=os.path.basename(path), children=[])
    try: lst = os.listdir(path)
    except OSError:
        pass #ignore errors
    else:
        for name in lst:
            if not(name.startswith('.')):
                fn = os.path.join(path, name)
                if os.path.isdir(fn):
                    tree['children'].append(make_tree(fn))
                else:
                    tree['children'].append(dict(name=name))
    return tree

def generateLanguage(language_path, nsf, capability_datamodel_path, nsf_catalogue_path):
    output_path = os.path.join(language_path,'language_'+nsf+'.xsd')
    try:
        ans = subprocess.check_output(['java', '-jar', 'jars/newLanguage.jar',capability_datamodel_path, nsf_catalogue_path, nsf, output_path])
        ans = ans.decode("utf-8")
        ans = ans.replace('\'','')
        ans = ans.replace('\n',' ')
        flash(ans)
    except subprocess.CalledProcessError as e:
        if(e.returncode==1):
            flash("Bad parameters for Language Generator Tool. Please check NSFCatalogue and NSF name.")

def generateLanguageNoGUI(language_path, nsf, capability_datamodel_path, nsf_catalogue_path):
    output_path = os.path.join(language_path,'language_'+nsf+'.xsd')

    ans = subprocess.check_output(['java', '-jar', 'jars/newLanguage.jar',capability_datamodel_path, nsf_catalogue_path, nsf, output_path])
    ans = ans.decode("utf-8")
    ans = ans.replace('\'','')
    ans = ans.replace('\n',' ')
    print(ans)

@app.route('/', methods=['GET', 'POST'])
def home():
    session.pop('_flashes', None)

    if request.method == 'POST':
        if 'converter' in request.form:
            return redirect(url_for('converter'))
        if 'langGen' in request.form:
            return redirect(url_for('languageGenerator'))
        if 'translator' in request.form:
            return redirect(url_for('translate'))
        if 'delconverter' in request.form:
            converter_path = os.path.join(app.config['UPLOAD_FOLDER'],'converter')
            for file in os.listdir(converter_path):
                os.remove(os.path.join(converter_path,file))
            return redirect(url_for('home'))
        if 'dellangen' in request.form:
            language_path = os.path.join(app.config['UPLOAD_FOLDER'],'languageGenerator')
            for file in os.listdir(language_path):
                if(file.endswith('.xsd')):
                    os.remove(os.path.join(language_path,file))
            return redirect(url_for('home'))
        if 'deltranslator' in request.form:
            translator_path = os.path.join(app.config['UPLOAD_FOLDER'],'translator')
            for file in os.listdir(translator_path):
                os.remove(os.path.join(translator_path,file))
            return redirect(url_for('home'))

    return render_template('home.html', tree=make_tree('uploads/'))

@app.route('/converter', methods=['GET', 'POST'])
def converter():
    allowed_extensions = {'xmi'}
    if request.method == 'POST':
        if 'home' in request.form:
            return redirect(url_for('home'))
        if 'upload' in request.form:
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            # If the user does not select a file, the browser submits an
            # empty file without a filename.
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file and allowed_file(file.filename, allowed_extensions):
                flash('File uploaded correctly')
                filename = 'definitivo.xmi'
                if(not os.path.isdir(os.path.join(app.config['UPLOAD_FOLDER'],'converter'))):
                    os.makedirs('uploads/converter/')
                file_path = os.path.join(app.config['UPLOAD_FOLDER'],'converter', filename)
                file.save(file_path)
                return redirect(url_for('converter', name=filename))
            elif not(allowed_file(file.filename, allowed_extensions)):
                    flash('File format is incorrect.')
                    return redirect(request.url)
        elif 'generate' in request.form:
            converter_path = os.path.join(app.config['UPLOAD_FOLDER'],'converter')
            file_to_convert = searchFileName(converter_path, '.xmi')
            if(file_to_convert is None):
                flash("Please submit Capability Data Model")
            else:
                converted_xsd = os.path.join(converter_path, file_to_convert)
                ans = subprocess.check_output(['java', '-jar', 'jars/newConverter.jar',converted_xsd, os.path.join(converter_path,'capability_data_model.xsd')])
                ans = ans.decode("utf-8")
                ans = ans.replace('\'','')
                ans = ans.replace('\n',' ')
                flash(ans)
            # else:
            #     flash('Please Generate XSD first')
    return render_template('converter.html')

@app.route('/langGen', methods=['GET', 'POST'])
def languageGenerator():
    allowed_extensions = {'xml'}
    language_path = os.path.join(app.config['UPLOAD_FOLDER'],'languageGenerator')
    converter_path = os.path.join(app.config['UPLOAD_FOLDER'],'converter')
    nsf_list = ['ipTables','XFRM','ethereumWebAppAuthz','StrongSwan','genericPacketFilter', 'Squid']
    if request.method == 'POST':
        if 'home' in request.form:
            return redirect(url_for('home'))
        if 'upload' in request.form:
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            # If the user does not select a file, the browser submits an
            # empty file without a filename.
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file and allowed_file(file.filename, allowed_extensions):
                flash('File uploaded correctly')
                filename = 'NSFCatalogue.xml'
                if(not os.path.isdir(os.path.join(app.config['UPLOAD_FOLDER'],'languageGenerator'))):
                    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'],'languageGenerator'))
                file_path = os.path.join(app.config['UPLOAD_FOLDER'],'languageGenerator', filename)
                file.save(file_path)
                f = open(file_path, "r+")
                l = f.readlines()
                l[1] = '<p:nsfCatalogue xmlns:p="http://untitled/uploads/converter/capability_data_model.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="capability_data_model.xsd">\n'
                f.close()
                f = open(file_path, "w+")
                f.writelines(l)
                f.close()
                return redirect(url_for('languageGenerator', name=filename))
            elif not(allowed_file(file.filename, allowed_extensions)):
                    flash('File format is incorrect.')
                    return redirect(request.url)
        elif 'generate' in request.form:
            capability_datamodel = searchFileName(converter_path, '.xsd')
            nsf_catalogue = searchFileName(language_path, '.xml')
            nsf = request.form['nsf']
            if(capability_datamodel is not None):
                if(nsf_catalogue is not None):
                    capability_datamodel_path = os.path.join(converter_path, capability_datamodel)
                    nsf_catalogue_path = os.path.join(language_path, nsf_catalogue)
                    if(nsf is not None):
                        generateLanguage(language_path, nsf, capability_datamodel_path, nsf_catalogue_path)
                    else:
                        flash('Please specify NSF name.')
                        return redirect(request.url)
                else:
                    flash('Please upload NSF Catalogue.')
                    return redirect(request.url)
            else:
                flash('Please upload Capability Data Model at /converter.')
                return redirect(request.url)
        elif 'generateAll' in request.form:
            capability_datamodel = searchFileName(converter_path, '.xsd')
            nsf_catalogue = searchFileName(language_path, '.xml')
            if(capability_datamodel is not None):
                if(nsf_catalogue is not None):
                    capability_datamodel_path = os.path.join(converter_path, capability_datamodel)
                    nsf_catalogue_path = os.path.join(language_path, nsf_catalogue)
                    for nsf in nsf_list:
                        generateLanguage(language_path, nsf, capability_datamodel_path, nsf_catalogue_path)

    return render_template('langGen.html')

@app.route('/translator', methods=['GET', 'POST'])
def translate():
    allowed_extensions = {'xml'}
    language_path = os.path.join(app.config['UPLOAD_FOLDER'],'languageGenerator')
    if request.method == 'POST':
        if 'home' in request.form:
            return redirect(url_for('home'))
        if 'upload' in request.form:
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            # If the user does not select a file, the browser submits an
            # empty file without a filename.
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file and allowed_file(file.filename, allowed_extensions):
                flash('File uploaded correctly')
                filename = 'RuleInstance.xml'
                if(not os.path.isdir(os.path.join(app.config['UPLOAD_FOLDER'],'translator'))):
                    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'],'translator'))
                file_path = os.path.join(app.config['UPLOAD_FOLDER'],'translator', filename)
                file.save(file_path)
                return redirect(url_for('translate', name=filename))
            elif not(allowed_file(file.filename, allowed_extensions)):
                    flash('File format is incorrect.')
                    return redirect(request.url)
        elif 'translate' in request.form:
            #"args": "../newLanguage/language_IpTables.xsd ../newLanguage/NSFCatalogue.xml ./IpTables_RuleInstance.xml -f",
                translator_path = os.path.join(app.config['UPLOAD_FOLDER'],'translator')
                if(searchFileName(translator_path, 'RuleInstance')):
                    rule_instance_path = os.path.join(app.config['UPLOAD_FOLDER'],'translator', 'RuleInstance.xml')
                    tree = ET.parse(rule_instance_path)
                    nsfName = tree.getroot().attrib['nsfName']
                    language_file = searchFileName(language_path, nsfName)
                    nsf_catalogue = searchFileName(language_path, '.xml')
                    destination_nsf = request.form['destnsf']
                    if(language_file is not None):
                        if(nsf_catalogue is not None):
                            language_file_path = os.path.join(language_path, language_file)
                            nsf_catalogue_path = os.path.join(language_path, nsf_catalogue)
                            translator_folder = os.path.join(app.config['UPLOAD_FOLDER'],'translator')

                            if (destination_nsf==''):
                                # os.remove(os.path.join(translator_folder,'policy.txt'))
                                try:
                                    ans = subprocess.check_output(['java', '-jar', 'jars/newTranslator.jar',language_file_path, nsf_catalogue_path, rule_instance_path, os.path.join(translator_folder,'policy.txt')])
                                    ans = ans.decode("utf-8")
                                    ans = ans.replace('\'','')
                                    ans = ans.replace('\n','<br>')
                                    if not("ERROR" in ans) and not("stop" in ans) and not("not allowed" in ans):
                                        flash(ans)
                                        translated_file = searchFileName(translator_folder, 'policy.txt')
                                        if(translated_file is not None):
                                            return send_from_directory(translator_folder, translated_file, as_attachment=True)
                                        else:
                                            flash('Translated policy not found.')
                                    else:
                                        if('stop' in ans):
                                            raise subprocess.CalledProcessError('','', stderr='One of the provided Rule Instances is not correct.')
                                        elif('not available' in ans):
                                            raise subprocess.CalledProcessError('','', stderr='Please check Destination NSF.')
                                        elif('not allowed' in ans):
                                            raise subprocess.CalledProcessError('','', stderr='Corrupted NSF Abstract Language. Please, generate it again.')
                                except subprocess.CalledProcessError as e:
                                    if(e.returncode==1):
                                        flash("Bad parameters for NSF Translator. Please check RuleInstance and Destination NSF name.")
                                    else:
                                        flash(e.stderr)
                            else:
                                try:
                                    ans = subprocess.check_output(['java', '-jar', 'jars/newTranslator.jar',language_file_path, nsf_catalogue_path, rule_instance_path, os.path.join(translator_folder,'policy.txt'), '+toNSF'+destination_nsf])
                                    ans = ans.decode("utf-8")
                                    ans = ans.replace('\'','')
                                    ans = ans.replace('\n',' ')
                                    if not("ERROR" in ans):
                                        flash(ans)
                                        translated_file = searchFileName(translator_folder, 'policy.txt')
                                        if(translated_file is not None):
                                            return send_from_directory(translator_folder, translated_file, as_attachment=True)
                                        else:
                                            flash('Translated policy not found.')
                                    else:
                                        if('not available' in ans):
                                            raise subprocess.CalledProcessError('','', stderr='Please check Destination NSF.')
                                except subprocess.CalledProcessError as e:
                                    if(e.returncode==1):
                                        flash("Bad parameters for NSF Translator. Please check RuleInstance and Destination NSF name.")
                                    else:
                                        flash(e.stderr)

                            return redirect(request.url)
                        else:
                            flash('Please upload NSF Catalogue.')
                            return redirect(request.url)
                    else:
                        flash('First Generate language for '+nsfName+' at /langGen.')
                        return redirect(request.url)
                else:
                    flash('First upload Rule Instance file.')
                    return redirect(request.url)
    return render_template('translator.html')

def initializeSecurityCapabilityModelLanguages():

        # This function can be used to initialize the Security Capability Model.

        # The following files should be available:
        # Put the definitivo.xmi file into the enforcer/uploads/converter folder
        # Put the NSFCatalogue.xml file into the enforcer/uploads/languageGenerator folder

        # At runtime the .xsd file for each Security Capability will be put in the
        # enforcer/uploads/languageGenerator folder

        converter_path = os.path.join(UPLOAD_FOLDER,'converter')
        language_path = os.path.join(UPLOAD_FOLDER,'languageGenerator')

        converted_xsd = os.path.join(converter_path, "definitivo.xmi")
        ans = subprocess.check_output(['java',
                                    '-jar',
                                    'jars/newConverter.jar',
                                    converted_xsd,
                                    os.path.join(converter_path,'capability_data_model.xsd')])
        ans = ans.decode("utf-8")
        ans = ans.replace('\'','')
        ans = ans.replace('\n',' ')
        print(ans)

        filename = 'NSFCatalogue.xml'
        file_path = os.path.join(UPLOAD_FOLDER,'languageGenerator', filename)
        f = open(file_path, "r+")
        l = f.readlines()
        l[1] = '<p:nsfCatalogue xmlns:p="http://untitled/uploads/converter/capability_data_model.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="capability_data_model.xsd">\n'
        f.close()
        f = open(file_path, "w+")
        f.writelines(l)
        f.close()

        nsf_to_generate = "iptables"
        capability_datamodel = searchFileName(converter_path, '.xsd')
        capability_datamodel_path = os.path.join(converter_path, capability_datamodel)
        nsf_catalogue_path = os.path.join(language_path, filename)
        generateLanguageNoGUI(language_path, nsf_to_generate, capability_datamodel_path, nsf_catalogue_path)


def cr_responder():
    """Runs the Central Repository response pipeline, that is the RabbitMQ consumer and producer"""

    queueName = 'secap'
    key = 'mspl.create'
    notification_consumer_config = {'host': 'fishymq.xlab.si',
                                    'port': 45672,
                                    'exchange' : 'tasks',
                                    'login':'tubs',
                                    'password':'sbut'}

    init_rabbit = RMQsubscriber(queueName, key, notification_consumer_config)
    init_rabbit.setup()

def run_flask():
    app.run(host='0.0.0.0', port=6000, debug=False)

def main():
    try:
        cr_thread = threading.Thread(target=cr_responder)
        flask_thread = threading.Thread(target=run_flask)
        cr_thread.start()
        flask_thread.start()
        cr_thread.join()
        flask_thread.join()
    except Exception as e:
        # Log the exception here
        print("Exception caught:", e)
        # Exit the program with a non-zero exit code
        sys.exit(1)

if __name__ == '__main__':
    # initializeSecurityCapabilityModelLanguages()
    main()