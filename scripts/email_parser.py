from O365 import *
import json, os, re, eml_parser, requests, shutil, urllib.parse, pymsteams, traceback, base64 


#Global Vars
hiveapikey = "YOURAPIKEYHERE"
webhook = "YOURWEBHOOKURLHERE"
hive_api_endpoint = "YOURENDPOINTHERE"
not_processed ='DIRECTORYLOCATIONHERE'
new_emails = 'DIRECTORYLOCATIONHERE'
suspicious_emails = 'DIRECTORYLOCATIONHERE'


class TeamsWebhook:


    def Send_Error(webhook_url, traceback):
        error_message = pymsteams.connectorcard(webhook_url)
        error_message.title("Error Alert")
        error_message.text('An error has occurred executing "email_parser.py"')
        traceback_section = pymsteams.cardsection()
        traceback_section.title("Traceback")
        traceback_section.text(traceback)
        error_message.addSection(traceback_section)
        error_message.send()
        

    def Send_Confirmation(refferer, subject):
        teams_confirmation = pymsteams.connectorcard(webhook)
        teams_confirmation.title("New Hive Alert Reported By: "+ refferer)
        teams_confirmation.color("#fad119")
        newsection = pymsteams.cardsection()
        teams_confirmation.addSection(newsection)
        teams_confirmation.text("Subject: "+ subject)
        teams_confirmation.addLinkButton("Investigate in The Hive Portal")
        teams_confirmation.send()


class EmailAnalyser:


    def Get_Email():

        #Poll mailbox for new email
        credentials = ("O365USER","O365PASS")   
        account = Account(credentials, auth_flow_type="credentials",tenant_id=("O365USERTENANT"), main_resource=("O365MAILBOX"))
        if account.authenticate():
            mailbox = account.mailbox()
            InboxFolder = mailbox.get_folder(folder_name="Inbox")
            Analyser_Processed_folder = InboxFolder.get_folder(folder_name="Analyser_Processed") 
            inbox = mailbox.inbox_folder()
            for message in inbox.get_messages(limit=4, query=mailbox.q().select("internet_message_headers")):
                    for header in message.message_headers:        
                        if header["name"] == "From":
                            email_referrer = str(header["value"].split("<")[1].split(">")[0])
                            for dateheader in message.message_headers:
                                if dateheader["name"] == "Date":
                                    date = dateheader["value"].replace(":", "-")
                                    date = date.replace(" ", "_") 
                                    date = date.replace("+", "")
                                    date = date.replace(",", "")
                                    filename = date + "_" + email_referrer
                                    filename = filename.split("@")[0]
                                    filename = filename.replace(".", "_")
                                    message.save_as_eml(to_path=new_emails+(filename + ".eml"))
                                    message.move(Analyser_Processed_folder)
                                    return email_referrer
                                else:
                                    message.move(Analyser_Processed_folder)
        for f in os.listdir("."):
            if f == "o365_token.txt":
                os.remove(f)
    

    def Email_Processor():

        #Check to see if reffered email has an email attachment
        for x in os.listdir(new_emails):
            if x.endswith(".eml"):
                email = eml_parser.parser.decode_email(new_emails+x,include_attachment_data=True)
                emlattached = False
                try:
                    for attachment in email["attachment"]:
                        if "message/rfc822" in attachment["content_header"]["content-type"] or str(attachment["filename"]).endswith(".eml"):
                            emlattached = True
                            filename = "Attached_Email_" + \
                            attachment["filename"] + "_" + \
                            attachment["hash"]["md5"] + "_.eml"
                            with open(filename, "wb") as a_out:
                                        a_out.write(base64.b64decode(attachment["raw"]))
                            if filename not in os.listdir(suspicious_emails):
                                    shutil.move(filename,suspicious_emails)
                                    os.remove(new_emails+x)
                            else:
                                os.remove(filename)
                                os.remove(new_emails+x)
                                pass 
                    if emlattached == False:
                        try:
                            os.remove(new_emails+x)
                        except FileNotFoundError:
                            pass
                except Exception:
                    try:
                        if x not in os.listdir(not_processed):
                                    shutil.move(new_emails+x,not_processed)
                        else:
                            os.remove(new_emails+x)
                    except FileNotFoundError:
                        pass
 

    def Main():
            
            #Parse reffered email and send to The Hive
            try:
                email_refferer = EmailAnalyser.Get_Email()
                EmailAnalyser.Email_Processor()
                for email_file in os.listdir(suspicious_emails):
                    email = eml_parser.parser.decode_email(suspicious_emails+email_file,include_attachment_data=True,include_raw_body=True)
                    if "received" in email["header"]["header"].keys(): 

                        #Attach email as observable
                        files = {email_file: open(suspicious_emails+email_file, "rb")}
                        observables = [{"dataType" : "file", "attachment": email_file}]

                        #The Hive alert mandatory fields payload
                        alert = {
                        "title": "",
                        "type": "Phishing Email",
                        "_createdBy": "YOURUSERNAMEHERE",
                        "source": "O365",
                        "sourceRef": "", 
                        "description": "Review the emails and observables provided within the alert to determine if the cause is malicious",
                        "observables": observables,
                        "tags": [],
                        "tlp":4
                        }

                        #Headers
                        alert["title"] = f'[Phishing Email] {email["header"]["subject"]}'
                        alert["sourceRef"] = f'MessageID: {email["header"]["header"]["x-ms-exchange-organization-network-message-id"]}'
                        observables.append({"dataType":"mail", "data": str(email_refferer),"tags":["mail-refferer"], "ignoreSimilarity":True,"tlp":4})
                        observables.append({"dataType":"mail", "data": email["header"]["from"],"tags":["mail-sender"], "ignoreSimilarity":True, "tlp":4})
                        observables.append({"dataType":"mail", "data": email["header"]["subject"],"tags":["mail-subject"]})
                        observables.append({"dataType":"mail", "data": email["header"]["to"], "tags":["mail-recipient"],"ignoreSimilarity":True})
                        if "cc" in email["header"].keys():
                            for cc in email["header"]["cc"]:
                                observables.append({"dataType":"mail", "data": cc, "tags":["CC","mail-recipients"], "ignoreSimilarity":True})
                        hops = email["header"]["received_ip"]

                        #Ignore Internal, multicast, loopback and broadcast IP addresses
                        ipv4_pattern = re.compile(
                        r"\b(?!(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                        r"192\.168\.\d{1,3}\.\d{1,3}|"
                        r"172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|"
                        r"4\.4\.1\.200|4\.4\.1\.0|3\.123\.5\.128\b)"
                        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
                        ip_list = ipv4_pattern.findall(str(hops))
                        ip_list_deduped = list(set(ip_list))
                        if ip_list_deduped:
                            for ip in ip_list_deduped:
                                observables.append({"dataType":"ip", "data": ip, "tags":["Headers: IP identified in Hops"], "tlp":0})
                        
                        #Attachments
                        if "attachment" in email:
                            for attachment in email["attachment"]:
                                observables.append({ "dataType": "hash", "data":attachment["hash"]["md5"], "tags":[attachment["filename"]], "tlp":4}) 
    
                        #Body
                        try:
                            if email["body"][0]["uri"]:
                                for url in email["body"][0]["uri"]:
                                    if "gbr01.safelinks.protection.outlook.com" in url:
                                        parse_url = urllib.parse.urlparse(url)
                                        query_dict = urllib.parse.parse_qs(parse_url.query)
                                        parsed_url = urllib.parse.unquote(query_dict["url"][0])
                                        observables.append({"dataType":"url", "data": parsed_url, "tags":["Body: Parsed URL from safelinks"], "tlp":0})
                                    elif "aka.ms" not in url and "w3.org" not in url:
                                        observables.append({"dataType":"url", "data": url, "tags":["Body: URL"], "tlp":0})
                        except KeyError:
                            pass
                        try:
                            if email["body"][0]["domain"]:
                                for domain in email["body"][0]["domain"]:
                                    if "safelinks.protection.outlook.com" not in domain and "aka.ms" not in domain and "w3.org" not in domain:
                                        observables.append({"dataType": "domain", "data": domain, "tags": ["Body: Domain"], "tlp":4})

                        except KeyError:
                            pass
                        try:
                            if email["body"][0]["email"]:
                                for mail in email["body"][0]["email"]:
                                    observables.append({"dataType":"mail", "data": mail, "tags":["Body: Email Address"]})
                        except KeyError:
                            pass

                        #Remove Duplicate Observables
                        unique_observables = set()
                        for d in observables[:]: 
                            if "data" in d:  
                                data_value = "".join(d["data"])  
                                if data_value in unique_observables:
                                    observables.remove(d)
                                else:
                                    unique_observables.add(data_value)

                        #Send Payload to API
                        response = requests.post(hive_api_endpoint+"/api/v1/alert",
                            files={
                                "_json": json.dumps(alert),
                                **files
                            },
                            headers={"Authorization": f"Bearer {hiveapikey}" }
                        )
                        if response.status_code == 201:
                            print("SUCCESS ", email_file,response.status_code, response.content,"\n",sep="\n")
                            TeamsWebhook.Send_Confirmation(str(email["header"]["to"]), str(email["header"]["subject"]))
                            files[email_file].close()
                            os.remove(suspicious_emails+email_file)
                        else:
                            print("FAILURE ", email_file,response.status_code, response.content,"\n",sep="\n") 
                            TeamsWebhook.Send_Error(webhook, response.text)
                            files[email_file].close()
                            try:
                                if email_file not in os.listdir(not_processed):
                                    shutil.move(suspicious_emails+email_file,not_processed)
                                    os.remove(suspicious_emails+email_file)
                            except FileNotFoundError:
                                pass      
        
            except Exception as e:

                #A general error has occurred within the script, send Teams notification
                tracebackinfo = traceback.format_exc()
                TeamsWebhook.Send_Error(webhook, tracebackinfo)
                files[email_file].close()

                try:
                    if email_file not in os.listdir(not_processed):
                        shutil.move(suspicious_emails+email_file,not_processed)
                        os.remove(suspicious_emails+email_file)
                except FileNotFoundError:
                    pass
            
if __name__ == "__main__":
    EmailAnalyser.Main()                   
