#
#
#   _____  .__                __________        __________                
#  /  _  \ |  |   ____ ___  __\______   \___  __\______   \_______  ____  
# /  /_\  \|  | _/ __ \\  \/  /|       _/\  \/  /|     ___/\_  __ \/  _ \ 
#/    |    \  |_\  ___/ >    < |    |   \ >    < |    |     |  | \(  <_> )
#\____|__  /____/\___  >__/\_ \|____|_  //__/\_ \|____|     |__|   \____/ 
#        \/          \/      \/       \/       \/                         
#
# Script : xc-report-usage.py
# Date   : 03/12/2024
# Version: 0.1


# -- Python library  
import requests 
import json
import xlsxwriter


# -- variable ------- begin 

xc_console_url= "https://<TENANT NAME>.console.ves.volterra.io/" 
xc_header_apitoken= {"Authorization":"APIToken <API TOKEN>"}



xc_namespaces = []

# -- variable ------- end


# Making a get request for the list of Namespaces.
var_url_namespace = xc_console_url+'api/web/namespaces'
response = requests.get(url=var_url_namespace,headers=xc_header_apitoken) 
print(response)

# Store JSON data in API_Data 
API_Data = response.json() 
print(str(API_Data))
API_Data = json.dumps(API_Data['items'], indent=2)

# DEBUG : json data
# print(API_Data) 

API_Data = json.loads(API_Data)

# Store list of namespace wihout "default" "shared" "system" in xc_namespaces
for items in API_Data:
    match items["name"]:
        case "system" | "shared" | "default":
           pass
        case _:
            #print(items["name"])
            xc_namespaces.append(items["name"])

print("---- list of Namespace ----")
print(xc_namespaces)



# Create a workbook and add a worksheet.
workbook = xlsxwriter.Workbook('xc-report-usage.xlsx')
worksheet = workbook.add_worksheet()

# Start from the first cell. Rows and columns are zero indexed.
row = 0
col = 0


#--  add header in worksheet

header_wks =["LB NAME","NAMESPACE","DESCRIPTION","DOMAINS","creation_timestamp","modification_timestamp","creator_id","State", 	"malicious_user_detection","api_discovery","api_definition","threat_mesh","ip_reputation","certificate_expiration","Certificat status"]

for items in header_wks:
    
    worksheet.write(0, col, items)
    col+=1
col=0    
row=1

    


# loop on namaspaces 
for items in xc_namespaces:
    print("*********************** NAMESPACES ******************************" + items)

    # Making a get request for the list of Namespaces.
    var_url_namespace = xc_console_url+"api/config/namespaces/"+items+"/http_loadbalancers?report_fields=null"
    response = requests.get(url=var_url_namespace,headers=xc_header_apitoken) 

    # Store JSON data in API_Data 
    API_Data = response.json() 
    API_Data = json.dumps(API_Data['items'], indent=2)
    API_Data = json.loads(API_Data)
    # DEBUG : json data
    #print(API_Data) 

    for _lb in API_Data:

        if _lb["name"] != "ves-io-workload-devportal-api" :
            print("> Nom du Loadbalancer : "  + _lb["name"])
            worksheet.write(row, col,     _lb["name"])

            print("> Namespace :"+ _lb["namespace"])
            worksheet.write(row, col+1,     _lb["namespace"])

            print("  - description       : "+ _lb["metadata"]["description"])
            worksheet.write(row, col+2,     _lb["metadata"]["description"])

            print("  - domaines          : "+ str(_lb["get_spec"]['domains']))
            worksheet.write(row, col+3,    str(_lb["get_spec"]['domains']))
                       

            #creationTimestamp: system_metadata.creation_timestamp,
            print("  - creation_timestamp     :"  + _lb["system_metadata"]["creation_timestamp"])
            worksheet.write(row, col+4,    _lb["system_metadata"]["creation_timestamp"])

            #modificationTimestamp: system_metadata.modification_timestamp,
            print("  - modification_timestamp :"  + str(_lb["system_metadata"]["modification_timestamp"]))
            worksheet.write(row, col+5,    str(_lb["system_metadata"]["modification_timestamp"]))


            #creatorId: system_metadata.creator_id,
            print("  - creator_id             :"  + _lb["system_metadata"]["creator_id"])
            worksheet.write(row, col+6,    _lb["system_metadata"]["creator_id"])
            
            #state: get_spec.state,
            print("  - State                  : "  + str(_lb["get_spec"]["state"]))
            worksheet.write(row, col+7,    str(_lb["get_spec"]["state"]))

            #disable_malicious_user_detection
            if "disable_malicious_user_detection"  in _lb["get_spec"]:
                print("  + disable_malicious_user_detection")
                worksheet.write(row, col+8,    "disable_malicious_user_detection")
            
            #enable_malicious_user_detection
            if "enable_malicious_user_detection" in _lb["get_spec"]:
                print("  + enable_malicious_user_detection")
                worksheet.write(row, col+8,    "enable_malicious_user_detection")

            #disable_api_discovery
            if "disable_api_discovery"  in _lb["get_spec"]:
                print("  + disable_api_discovery")
                worksheet.write(row, col+9,    "disable_api_discovery")
            
            #enable_api_discovery
            if "enable_api_discovery" in _lb["get_spec"]:
                print("  + enable_api_discovery")
                worksheet.write(row, col+9,    "enable_api_discovery")

            # disable_api_definition / api_specification api_definition

            #disable_api_definition
            if "disable_api_definition"  in _lb["get_spec"]:
                print("  + disable_api_definition")
                worksheet.write(row, col+10,    "disable_api_definition")
                
                # 
            #enable_api_definition
            if "api_specification" in _lb["get_spec"]:
                print("  + enable_api_discovery")
                worksheet.write(row, col+10,    "enable_api_discovery")

            #disable_threat_mesh
            if "disable_threat_mesh"  in _lb["get_spec"]:
                print("  + disable_threat_mesh")
                worksheet.write(row, col+11,    "disable_threat_mesh")
                # 
            #enable_threat_mesh
            if "enable_threat_mesh" in _lb["get_spec"]:
                print("  + enable_threat_mesh")
                worksheet.write(row, col+11,    "enable_threat_mesh")

            # enable_ip_reputation
            #enable_ip_reputation
            if "disable_ip_reputation"  in _lb["get_spec"]:
                print("  + disable_ip_reputation")
                worksheet.write(row, col+12,    "disable_ip_reputation")
                # 
            #enable_ip_reputation
            if "enable_ip_reputation" in _lb["get_spec"]:
                print("  + enable_ip_reputation")
                worksheet.write(row, col+12,    "enable_ip_reputation")



            #certExpiration: get_spec.downstream_tls_certificate_expiration_timestamps,
            print("  > certificate_expiration : "  + str(_lb["get_spec"]["downstream_tls_certificate_expiration_timestamps"]))
            worksheet.write(row, col+13,    str(_lb["get_spec"]["downstream_tls_certificate_expiration_timestamps"]))

            #certState: get_spec.cert_state,
            print("  > "  + str(_lb["get_spec"]["cert_state"]))
            worksheet.write(row, col+14,    str(_lb["get_spec"]["cert_state"]))


        row += 1
    

workbook.close()   


    
    


   