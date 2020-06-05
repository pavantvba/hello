#!/usr/bin/python
import json
import requests
from datetime import date, datetime
#import urllib
import gzip
import configparser
import os
import smtplib
import boto3
from datetime import datetime
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
from email.MIMEBase import MIMEBase
from email import Encoders
#from nvd_db_connector import insert_data as insert_data
import nvd_db_connector


global cve_exclude_list
cve_exclude_list = list()
cve_findings = dict()
matched_cve_findings = dict()
config = configparser.ConfigParser()

def load_nvdcve_data(json_data_file):
	try:

		#with open('nvdcve-1.0-modified.json') as json_file:
		#json_data_file = "data/nvdcve-1.0-2019-"+ str(date.today()) +".json"
		#json_data_file = 'data/nvdcve-1.0-2019-2.json'
		print json_data_file
		with open(json_data_file) as json_file:
			jsonObject = json.load(json_file)
			load_cve_items(jsonObject)
	except Exception as exp:
		print "Exception occurred while processing nvdcve data file ", json_data_file 

def load_cve_items(jsonObject):
	cve_items_object = fetch_cve_items_data(jsonObject)
	#print "--- ", cve_items_object
	for cve_item in cve_items_object:

		cve_id = fetch_cve_id(cve_item)
		if cve_id in cve_findings.keys():
			print "CVE item already exists, hence no need to add duplicate entry.."
		else:
			cve_findings[cve_id] = dict()
			values_dict = dict()
		
			values_dict["BaseScore"] = fetch_base_score(cve_item)
			values_dict["ImpactScore"] = fetch_impact_score(cve_item)
			values_dict["Severity"] = fetch_impact_severity(cve_item)
			values_dict["Description"] = fetch_impact_description(cve_item)
			values_dict["Vendor_Name"] = fetch_vendor_name(cve_item)	
			values_dict["Product_Name"] = fetch_product_name(cve_item)
			#print values_dict
			cve_findings[cve_id] = values_dict

	search_vulnerable_products()
	print len(cve_findings)
	cve_findings.clear()
	print cve_findings
	print len(cve_findings)

def fetch_cve_items_data(jsonObject):
	return jsonObject["CVE_Items"]

def fetch_impact_score(cve_item):
	if len(cve_item["impact"]) > 0: 
		#print cve_item["impact"]["baseMetricV2"]["impactScore"]
		return cve_item["impact"]["baseMetricV2"]["impactScore"]
	else:
		#print "No impact info"
		return ""

def fetch_base_score(cve_item):
	if len(cve_item["impact"]) > 0: 
		#print cve_item['impact']['baseMetricV2']['cvssV2']['baseScore']
		return cve_item['impact']['baseMetricV2']['cvssV2']['baseScore']
	else:
		#print "No baseScore info"
		return ""

def fetch_impact_description(cve_item):
	return cve_item["cve"]["description"] 	

def fetch_impact_severity(cve_item):
	if len(cve_item["impact"]) > 0: 
		#print "Severity:", cve_item
		return cve_item["impact"]["baseMetricV2"]["severity"]
	else:
		return ""

def fetch_cve_id(cve_item):
	return cve_item["cve"]["CVE_data_meta"]["ID"]

def fetch_vendor_name(cve_item):

	if len(cve_item["cve"]["affects"]["vendor"]["vendor_data"]) > 0:
		return cve_item["cve"]["affects"]["vendor"]["vendor_data"][0]["vendor_name"]
	else:
		return ""

def fetch_product_name(cve_item):
	prod_name_dict = dict()
	if len(cve_item["cve"]["affects"]["vendor"]["vendor_data"]) > 0:
		product_data = cve_item["cve"]["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"]
		#print "Multiple Product Names:"
		for prod_name in product_data:
			versions_data = prod_name["version"]["version_data"]
			version_info_str = fetch_impacted_versions_data(versions_data)
			#print prod_name["product_name"], version_info_str
			prod_name_dict[prod_name["product_name"]] = version_info_str
		return prod_name_dict

	else:
		return prod_name_dict

def fetch_impacted_versions_data(versions_data):
	version_info_str = ""
	for version in versions_data:
		version_info_str = version_info_str + version["version_value"] + "  "
	return version_info_str
		
def fetch_matched_vulnerable_products():
	for cve_key, cve_values in matched_cve_findings.items():
		print "Key : Values ", cve_key, cve_values

def get_value(param):
	return get_config_details('product_file','products_list_file_path')

def read_products_file():
	#prod_file_name = get_value("product_file")
	#print "Products file name: ",prod_file_name 
	#file_object = open(prod_file_name,'r')
	#return file_object.readlines()
	product_list_from_db = nvd_db_connector.fetch_data_from_db("product_information","dummy")
	if (len(product_list_from_db) != 0):
		print("Fetched Products list from database to scan ", product_list_from_db)
		return product_list_from_db
	else:
		print ("There are no products listed for scanning")
		return []

def search_vulnerable_products():

	products_list = read_products_file()
	print "Searching vulnerable products information in the database"
	#print "Products_list_from_file: ", products_list

	for prod_entry in products_list:
		product_from_file = prod_entry.split(" ")
		for cve_id, cve_value in cve_findings.items():
			for cve_product_name in cve_value["Product_Name"]:
				if(product_from_file[0].strip() == cve_product_name):
					#print "Passing product version number and other details to check_version_number_exists_and_store method..."
					check_version_number_exists_and_store(cve_id, cve_value, product_from_file[1].strip())
					matched_cve_findings[cve_id] = dict()
					matched_cve_findings[cve_id] = cve_value
					#print "=============================="
					#print ("Control in SEARCH vulnerable_products ", cve_id, cve_value)
					#print "=============================="
				#else:
				#	print ("Product number doesn't exists hence not added to matched_cve_findings dictonary....")

def check_version_number_exists_and_store(cve_id, cve_value, version_number):
	key_temp = ""
	value_temp =""

	for key in cve_value["Product_Name"].keys():
                key_temp = key_temp + key + "\n"

        for value in cve_value["Product_Name"].values():
                value_temp = value_temp + value + "\n"
	
	#print "Version Number : ", version_number

	if version_number in value_temp:
		if(check_cveid_in_exclude_list(cve_id)):
			print ("Constructing object to insert data to the database..........")
			db_values = (cve_id, str(cve_value["BaseScore"]), str(cve_value["ImpactScore"]), key_temp, value_temp, str(cve_value["Vendor_Name"]), cve_value["Severity"], str(cve_value["Description"]["description_data"][0]["value"]))

			#print ("Database values to store:", db_values)
			nvd_db_connector.insert_data(db_values)



# This was serch_vulnerable_products method has been renamed with construct_email_message. Business logic should be updated in this method 

def construct_email_message():
	try:
		mail_message = ""
		mail_message += "<html><head><style> table { border-collapse: collapse;} table, td, th { border: 1px solid black;}</style></head><body>"
		vul_records = nvd_db_connector.fetch_data_from_db("vulnerability_information", "dummy")
		if (len(vul_records) >0 ):
			email_header_message = get_config_details('nvd_data_config','mail_header_message')
			mail_message += "<h3>" + email_header_message + "</h3><br> <table border=1> <tr bgcolor='#A9A9F5'><th>CVE_ID</th><th>Base Score</th><th>Impact Score</th><th>Product Name </th><th> Versions</th><th>Vendor Name</th><th>Severity</th><th>Description</th></tr>"
			for record in vul_records:
				#print record
				mail_message += "<tr>"
				dummy_var = True
				for value in record:
					#print value
					if(dummy_var):
        					mail_message += "<td><a href=" + get_config_details('nvd_data_config', 'cve_site_path')+ value +">"+ value + "</a></td>"
					else:
        					mail_message += "<td>"+ value + "</td>"
					dummy_var = False
			mail_message +="</tr></table>"
		else:
			print ("No records to send e-mail/process...")	
			mail_message += "<h2>There are no new vulnerablities found to report!</h2>"

		mail_message +="</body></html>"
		#print mail_message
		send_email_notification(mail_message)
		copy_to_aws_s3(mail_message)
		#print "Vulnerable product:", cve_id, cve_product_name
	
	except Exception as exp:
		print ("Exception occurred while constructing e-mail message: ", exp)



def send_email_notification(email_body):
        try:
                msg = MIMEMultipart()
                msg['From'] = get_config_details('SMTP','from_address')
                msg['To'] = get_config_details('SMTP','to_address')
                msg['Subject'] = get_config_details('SMTP','mail_subject')
                msg.attach(MIMEText(email_body, 'html'))
                password = get_config_details('SMTP','password')
                email = smtplib.SMTP(get_config_details('SMTP','server_address'))
                email.starttls()
                email.login(msg['From'], password)
                mail_response_msg = email.sendmail(msg['From'], msg['To'].split(','), msg.as_string())
                email.quit()
		if (len(mail_response_msg) == 0):
                	print "E-mail has been sent."
		else:
			print ("Failed to send e-mail ", mail_response_msg)
        except Exception as exp:
                print "Exception occurred while sending e-mail notification: " + exp.message


def copy_to_aws_s3(email_body):
	try:
		print ("Writing to S3....")
		#s3 = boto3.resource( 's3', region_name='us-east-1', aws_access_key_id=KEY_ID, aws_secret_access_key=ACCESS_KEY)
		s3 = boto3.resource( 's3', region_name='us-east-1')
		print ("S3 boto3 object has been created....")
		bucket_name = 'caas-devops'
		date_string = datetime.now()
		print "File name is getting generated..."		
		file_name = 'vulnerability-reports/vulnerability-findings-'+ date_string.strftime("%m-%d-%Y-%H-%M-%S")+'.html'
		#file_name = 'vulnerability-reports/vulnerability-findings-08-05-2019-12:34:1.html'
		
		print ("Before writing to s3.....", bucket_name+file_name)
		s3.Object(bucket_name, file_name).put(Body=email_body)
		print ("Writing to S3 completed!")
	except Exception as exp:
		print ("Exception occurred while writing to S3 ", exp)


	
def get_config_details(section_name, key):
        try:
                return config.get(section_name,key)
        except Exception as e:
                print "Requested element doesn't exists : " + e.message

#def download_nvd_meta_file():
	

def download_nvd_json_data_files():
	nvd_json_data_file_base_url = get_config_details('nvd_data_config','nvd_json_data_file_base_url')
	#nvd_json_data_files = get_config_details('nvd_data_config','nvd_json_data_files')
	nvd_json_data_files = nvd_db_connector.fetch_data_from_db("nvd_database", "download")
	if (len(nvd_json_data_files) == 0):
		print ("There are no NVD Json database files requested to download")
	else: 
		nvd_json_data_folder_path = get_config_details('nvd_data_config','nvd_json_data_folder')
		#for nvd_file_item in nvd_json_data_files.split(", "):
		for nvd_file_item in nvd_json_data_files:
			try:
				download_file(nvd_json_data_file_base_url+nvd_file_item, nvd_json_data_folder_path+nvd_file_item)
				unzip_file(nvd_json_data_folder_path, nvd_file_item)
			except Exception as exp:
				print "Exception occurred while loading json files", exp

def scan_nvd_json_data_files():
        nvd_json_data_files = nvd_db_connector.fetch_data_from_db("nvd_database", "scan")
	if (len(nvd_json_data_files) == 0):
		print ("There are not NVD Json Database files requested to scan vulnerabilities")
	else:
        	nvd_json_data_folder_path = get_config_details('nvd_data_config','nvd_json_data_folder')
	        for nvd_file_item in nvd_json_data_files:
        	        try:
                	        nvd_file_item_new = nvd_file_item[:-3]
	                       	print "scanning the file " + nvd_file_item + " has been started"
				load_nvdcve_data(nvd_json_data_folder_path+nvd_file_item_new)
			except Exception as exp:
				print "Exception occurred while scanning/loading the json files", exp


def download_file(url, file):
	try:
		print url 
		response = requests.get(url)
		with open(file, 'wb') as file_handler:
			file_handler.write(response.content)
		if response.status_code == 200:
			print (response.headers['content-type'])
			print "file " + file + " has been downloaded"
	except Exception as exp:
		print "Exception occurred while loading json files", exp
	

def download_nvd_modified_file():
	nvd_json_data_file_base_url = get_config_details('nvd_data_config','nvd_json_data_file_base_url')
	#nvd_json_modified_file = get_config_details('nvd_data_config','nvd_json_modified_data_file')
	[nvd_json_modified_file] = nvd_db_connector.fetch_data_from_db("nvd_database","weekly")
	nvd_json_data_folder_path = get_config_details('nvd_data_config','nvd_json_data_folder')
	download_file(nvd_json_data_file_base_url+nvd_json_modified_file, nvd_json_data_folder_path+nvd_json_modified_file)
	print "Calling unzip_file method"
	unzip_file(nvd_json_data_folder_path, nvd_json_modified_file)

def unzip_file(folder_name,file_name):
	try:
		print "Reading gunzip file...", file_name
		input = gzip.GzipFile(folder_name+file_name, 'rb')
		content = input.read()
		input.close()

		print "Extracting and writing gunzip file...", file_name
		new_file_name = file_name[:-3]
		output = open(folder_name+new_file_name, "wb")
		output.write(content)
		output.close()
		print "Successfully extracted file content and now deleting the compressed file"
		delete_file(folder_name+file_name)
		
	except Exception as exp:
		print "Exception occurred while extracting the file", exp
	
def delete_file(file_name):
	try:
		if os.path.exists(file_name):
			os.remove(file_name)
		else:
			print "File "+ file_name + " does not exist"
	except Exception as exp:
		print "Exception occurred while deleting the file", file_name

def load_exclude_cve_ids():
	exclude_list = nvd_db_connector.fetch_data_from_db("exclude_list", "all")
	cve_exclude_list.append(exclude_list)
	print "Exclude List:", cve_exclude_list
	#return exclude_list

def check_cveid_in_exclude_list(cve_id):

	print "CVE_Id in exclude method ", cve_id, cve_exclude_list
	if (str(cve_id.strip()) in cve_exclude_list[0]):
		print "########cve_id exists in exclude list", cve_id
		return False
	else:
		print "=========cve_id does not exist in exclude list", cve_id
		return True


def main():
	try:
                config.read("../conf/nvd_conf.ini")
                print "Started.."
		print "Loading exclude cveids..."

		# Remove comments 
		load_exclude_cve_ids()
		#cve_exclude_list = load_exclude_cve_ids()
		print "Loading exclude cveids complete!"

		print "Downloading NVD databases.."
		download_nvd_json_data_files()
		print "Downloading NVD databases complete!"

		print "Scanning products information..."
		scan_nvd_json_data_files()
		print "Scanning products information complete!"

		#download_nvd_modified_file()

		####################################
		# No need to uncomment the followig 2 lines
		#load_nvdcve_data()   
		#fetch_matched_vulnerable_products()
		#####################################


		#Remove command of construct_email_message and search_vulnerable_products
		#print "Sending email with scanned information..."
		construct_email_message()
		#print "email has been sent successfully!"
		#search_vulnerable_products()
		#nvd_db_connector.fetch_data_from_db("vulnerability_information", "dummy")

        except Exception as exp:
                print "Exception occurred while reading configuration file: " + exp.message
		print exp


	
main()


