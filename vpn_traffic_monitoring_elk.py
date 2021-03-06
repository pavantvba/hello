#!/usr/bin/env python
import sqlite3
from optparse import OptionParser
from datetime import *
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import json
import urllib,urllib2
import os

list_bytes_in,list_bytes_out,list_bytes_total,li =[],[],[],[]

recipients = ['sahaj.mahajan@caastle.com','pavan.tvba']
body =''
parser = OptionParser()

parser.add_option("--time", dest="time_minus", default=60,
                help="This is the time we want to minus from current time to get results")

parser.add_option("--path", dest="path", default="/usr/local/openvpn_as/etc/db/log.db",
                help="Name of the bucket")

parser.add_option("--bytes_out", dest="bytes_out", default=52428800,  # 50MB
                help="Threshold value of bytes out")

parser.add_option("--bytes_in", dest="bytes_in",
                help="Threshold value of bytes in")

parser.add_option("--bytes_total", dest="bytes_total",
                help="Threshold value of total bytes")

(options, args) = parser.parse_args()

current_time = datetime.now()
end_time = current_time - timedelta(minutes=options.time_minus)
now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
print current_time
print end_time

##Mapper Data
#mapper_data = {
#    "mappings": {
#        "vpn_logs": {
#            "properties": {
#                "date": {
#                    "type": "date",
#                    "format": "yyyy-MM-dd HH:mm:ss"
#                    }
#                }
#            }
#        }
#    }

mapper_data = {
    "mappings": {
        "vpn_logs": {
            "properties": {
                "date": {
                    "type": "date",
                    "format": "yyyy-MM-dd HH:mm:ss"
                    }
                }
            }
        }
    }


# test_query = ("""Select username,datetime(start_time, "unixepoch", "localtime"),datetime(timestamp, "unixepoch", "localtime"),real_ip,vpn_ip,bytes_in,bytes_out,bytes_total,duration from log where datetime(timestamp, "unixepoch", "localtime") > \"%s\" and datetime(timestamp, "unixepoch", "localtime") < \"%s\" and active=1 order by datetime(timestamp, "unixepoch", "localtime") """) %(str("2019-07-08 15:28:27"),str("2019-07-09 14:39:09"))
# print test_query

query = ("""Select username,datetime(start_time, "unixepoch", "localtime"),datetime(timestamp, "unixepoch", "localtime"),real_ip,vpn_ip,bytes_in,bytes_out,bytes_total,duration from log where datetime(timestamp, "unixepoch", "localtime") > \"%s\" and datetime(timestamp, "unixepoch", "localtime") < \"%s\"  and active=1 order by datetime(timestamp, "unixepoch", "localtime") """) %(str(end_time),str(current_time))
print query

def send_email(email_body,recipients,subject):
    msg = MIMEMultipart()
    msg['From'] = 'sre-help@gwynniebee.com'
    msg['To'] = (',').join(recipients)
    msg['Subject'] = subject
    msg.attach(MIMEText(email_body, 'html'))
    password = '$bee1000'
    email = smtplib.SMTP('smtp.gmail.com:587')
    email.starttls()
    email.login(msg['From'], password)
    email.sendmail(msg['From'], recipients, msg.as_string())
    email.quit()

#Function for creating connection with sqlite3
def sqlite_connect(path):
    try:
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        return conn,cursor
    except Exception as e:
        print('Error:', e)

#Fucntion for fetching data from the sqlite3
def getting_data():
    try:
        print "Creating Connection with Sqlite3..."
        conn,cursor = sqlite_connect(options.path)
        print "Connection Created"
        #Executing query to read data
        print "Executing query to get data..."
        print "Query =",query
        cursor.execute(query)
        # print cursor.fetchall()
        conn.commit()
        records = cursor.fetchall()
        print "Records: ", records
        return records

    except Exception as e:
        print('Error:', e)

    finally:
        try:
            cursor.close()
            conn.close()
        except:
            print ("Error in closing conn")

#function to convert data generated by sqlite3 query to json
def make_tuple_json():

    data = getting_data()
    for tup in data:
        # print tup
        dicty = {}
        dicty["date"] = now
        dicty["username"] = tup[0]
        dicty["starttime"] = tup[1]
        dicty["currenttime"] = tup[2]
        dicty["realip"] = tup[3]
        dicty["vpnip"] = tup[4]
        dicty["bytesin"] = tup[5]
        dicty["bytesout"] = tup[6]
        dicty["bytestotal"] = tup[7]
        dicty["duration"] = tup[8]

        ##Appending dictionaries into list
        li.append(dicty)
    print "Tuple Dat", li, len(li)
    return li

#Function for creating index and pushing the data to elasticsearch
def post_es(mapper_data):

    index_list = []
    url = "http://es-mon.logmon.gwynniebee.com:9200"
    headers = {'content-type': 'application/json'}
    today = datetime.today()
    weekyear = str(today.year) + '.' + str(today.strftime("%V"))
    #print weekyear
    index_url = url + "/vpn-logs*"
    index_name = "vpn-logs-%s" % (weekyear)
    mapper_url = url + "/%s" % (index_name)
    data_url = mapper_url + "/logs_data"

    #Getting the list of indices
    req1 = urllib2.Request(index_url)
    response1 = urllib2.urlopen(req1)
    print "Response1 =",response1
    es_indices = json.load(response1)
    print "es_indices = ",es_indices

    for key in es_indices.keys():
        index_list.append(es_indices[key]['settings']['index']['provided_name'])
    print "\nList of vpn indexes present = ",index_list

    #Checking if index is present or not, if not create an index
    #if not index_name in index_list:
    #    mapper_data = json.dumps(mapper_data)
    #    req2 = urllib2.Request(mapper_url)
    #    req2.add_header('content-type', 'application/json')
    #    req2.get_method = lambda: 'PUT'
    #    #req2 = urllib2.Request(mapper_url,mapper_data,headers)
    #    response2 = urllib2.urlopen(req2)
    #    print "\n Response2 = ",json.load(response2)
    if not index_name in index_list:
        mapper_data = json.dumps(mapper_data)
        req2 = urllib2.Request(mapper_url)
        req2.add_header('content-type', 'application/json')
        req2.get_method = lambda: 'PUT'
        req2.data = mapper_data
        #req2 = urllib2.Request(mapper_url,mapper_data,headers)
        response2 = urllib2.urlopen(req2)
        print "\n Response2 = ",json.load(response2)
    else:
        print "Index is already present"

    #Pushing the actual vpn logs to elasticsearch
    logs_data = make_tuple_json()
    for logs in logs_data:
        load_logs = json.dumps(logs)
        req3 = urllib2.Request(data_url, load_logs, headers)
        response3 = urllib2.urlopen(req3)
        print json.load(response3)


##Main starts here

#Calling function to push data into elasticsearch
post_es(mapper_data)
#make_tuple_json()

