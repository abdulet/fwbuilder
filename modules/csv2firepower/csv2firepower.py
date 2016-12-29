#!/usr/bin/python
#
# Generated FMC REST API sample script
#
 
import re
import ipaddress as ip
import argparse
import config as cfg
import sys
import codecs
import socket
import json
import sys
import requests

#Adds libs dir to sys.path
sys.path.insert( 0, cfg.libdir )
#import expect module
import expect

#Dictionary to store all url objects
urls = {}

#Dictionary to store all addresses objects
ipobjectsbyip = {}
#Dictionary to store not imported addresses because are dupplicated
duplicatedaddressbyname = {}

#Dictionary to store all elementes already added to any checkpoint script
#its mission is avoid duplicated objects
addedelements = {} 
addedelements[ "object" ] = []
addedelements[ "service" ] = []

#Set the variables from config file
csv_header=cfg.csv_header
FMCip=cfg.SMSip
FMCuser=cfg.SMSuser
FMCpwd=cfg.SMSpwd
path = cfg.path 
dir_csv = cfg.dir_csv
dir_cp = cfg.dir_cp
logfile = cfg.logfile
avoidduplicatedobjects = cfg.avoidduplicatedobjects
groupby = cfg.groupby
rulenumber = cfg.rulenamenumber
rulenamenumber = cfg.rulenamenumber
policyname = cfg.policyname


#Module Specific variables
FMCurl = "https://" + FMCip

#Stores the request object
r = None

#Store the request headers
headers = {}

#Sotores de default domain, if only one defined
defaultdomain = "e276abec-e0f2-11e3-8169-6d9ed49b625f"

#Generic global functions, should be in a lib to be imported in each module (ex. fwbuilder)
def objectexists( name, objtype ):
    """
    Checks if the object exists in the elements dictionary
    """

    objtype = objtype.lower()
    
    if objtype not in addedelements:
        return False
    
    if name.lower() in addedelements[ objtype ]:
        return True
    else:
        return False 

def objectadded( name, objtype, uid=None ):
    """
    Avoid duplicity of elements, checking if it exists
    """

    objtype = objtype.lower()
    if objtype not in addedelements:
        addedelements[ objtype ] = {}
    if name.lower() in addedelements[ objtype ]:
        if addedelements[ objtype ][ name.lower() ] = "" and uid is not None:
            addedelements[ objtype ][ name.lower() ] = uid
        else:
            print "Duplicated element " + name.lower() + " of type " + objtype
        return True
    else:
        addedelements[ objtype ][ name.lower() ] = uid
        return False

def getcsvlines( fname ):
    f = codecs.open( path + "/" + dir_csv + "/" + fname, "r", "utf-8" )
    lines = []
    for line in f.readlines():
        lines.append( line.replace("\n", "") )
    f.close()

    return lines[1::]

def atomizerules ( rules ):
    """
    Expand all rules so one line is for one source, one destination
    and one service.
    """

    atomized = []
    for rule in rules:
        name,action,log,source,destination,application,disabled = rule.split( "," )
        for src in source.split(" "):
            for dst in destination.split(" "):
                for app in application.split(" "):
                    atomized.append( name + "," + action + "," + log + "," + src + "," + dst + "," + app + "," + disabled )
    return atomized

def groupbydestination( rules ):
    retrules = {}
    for line in rules:
        #Loop each rule to find other ones to group with
        name,action,log,source,destination,application,disabled = line.split( "," )
        #Group rules by destination
        key= ",".join([ destination, action, disabled, application ])
        if not key in retrules:
            retrules[ key ] = {}
            retrules[ key ][ "sources" ] = []
        if not "log" in retrules[ key ] or ( "log" in retrules[ key ] and log == "Log" ):
            retrules[ key ][ "log" ] = log
        if not source in retrules[ key ][ "sources" ]:
            retrules[ key ][ "sources" ].append( source )
    return retrules

def groupbysource( rules ):
    retrules = {}
    for line in rules:
        #Loop each rule to find other ones to group with
        name,action,log,source,destination,application,disabled = line.split( "," )
        #Group rules by source
        key= ",".join([ source, action, disabled, application ])
        if not key in retrules:
            retrules[ key ] = {}
            retrules[ key ][ "destinations" ] = []
        if not "log" in retrules[ key ] or ( "log" in retrules[ key ] and log == "Log" ):
            retrules[ key ][ "log" ] = log
        if not destination in retrules[ key ][ "destinations" ]:
            retrules[ key ][ "destinations" ].append( destination )
    return retrules

def groupbyservice( rules ):
    retrules = {}
    for line in rules:
        #Loop each rule to find other ones to group with
        name,action,log,source,destination,application,disabled = line.split( "," )
        #Group rules by services
        direction = "in"
        srcip = source.replace( "imphost_", "" )
        try:
            if ip.ip_address( unicode( srcip ) ).is_private:
                direction = "out"
        except:
            print "Invalid IP: " + srcip
            continue
        key= ",".join([ application, action, disabled, direction ])

        if not key in retrules:
            retrules[ key ] = {}
            retrules[ key ][ "destinations" ] = []
            retrules[ key ][ "sources" ] = []
        if not "log" in retrules[ key ] or ( "log" in retrules[ key ] and log == "Log" ):
            retrules[ key ][ "log" ] = log
        if not destination in retrules[ key ][ "destinations" ]:
            retrules[ key ][ "destinations" ].append( destination )
        if not source in retrules[ key ][ "sources" ]:
            retrules[ key ][ "sources" ].append( source )        
    return retrules

def optimizerules ( rules ):
    """
    Group rules that shares same source, destination, or action
    Three variants:
       1 "samedest": Same destination, service, action and status ( enabled or disabled)
       2 "samesrc" : Same source, service, action and status ( enabled or disabled)
       3 "samesrv" : Same service, action and status ( enabled or disabled)
    Then count wich variant have less rules and apply that to group the final rules
    """
    totalrules = len( rules )
    rules = atomizerules ( rules )
    grouped = {} # store grouped rules
    grouped [ "samedest" ] = groupbydestination( rules )
    grouped [ "samesrc" ] = groupbysource ( rules )
    grouped [ "samesrv" ] = groupbyservice ( rules )
    
    groupby = args[ "groupby" ]

    if groupby == "source":
        lessrules = "samesrc"
    elif groupby == "destination":
        lessrules =  "samedest"
    elif groupby == "service":
        lessrules = "samesrv"
    elif groupby == "auto":
        lessrules = sorted ( { "samedest": len( grouped [ "samedest" ] ), "samesrc": len( grouped [ "samesrc" ] ), "samesrv": len( grouped [ "samesrv" ] ) } )[ -1 ]

    retrules = []
    i=rulenamenumber
    for key, value in grouped[ lessrules ].items():
        #Build csv format again
        log = value[ "log" ]
        if lessrules == "samedest":
            destination, action, disabled, application = key.split(",")
            source = " ".join( value["sources"] )
            name = destination
        elif lessrules == "samesrc":
            source, action, disabled, application = key.split(",")
            source = " ".join( value["destinations"] )
            name = source
        elif lessrules == "samesrv":
            application, action, disabled, direction = key.split(",")
            source = " ".join( value["sources"] )
            destination = " ".join( value["destinations"] )
            name = direction + "_" + application
        retrules.append( ",".join( [ name,action,log,source,destination,application,disabled ] ) )
        i+=1
    return retrules

def unhiderules ( rules ):
    #Ensure that no rule hides other one
    name,action,log,source,destination,application,disabled = line.split( "," )

def writeusedobjectstofile():
    #writes every used ip objects and groups and services to a file
    f = codecs.open("output/used_objects.txt", "w", "utf-8")
    for elemtype, elem in addedelements:
        f.write( "####################################" + elemtype + "#########################################################" )
        f.write( "\n".join( addedelements[ elemtype ] ) + "\n" )
    f.close()

############################################# Module specific functions ###########################################################
def auth():
    #Authenticates to the api system
    if len(sys.argv) > 1:
        FMCuser = sys.argv[1]
    if len(sys.argv) > 2:
        FMCpwd = sys.argv[2]
                   
    headers = {'Content-Type': 'application/json'}
    api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
    auth_url = FMCurl + api_auth_path
    try:
        # 2 ways of making a REST call are provided:
        # One with "SSL verification turned off" and the other with "SSL verification turned on".
        # The one with "SSL verification turned off" is commented out. If you like to use that then 
        # uncomment the line where verify=False and comment the line with =verify='/path/to/ssl_certificate'
        # REST call with SSL verification turned off: 
        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(FMCuser,FMCpwd), verify=False)
        # REST call with SSL verification turned on: Download SSL certificates from your FMC first and provide its path for verification.
        # r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(FMCuser,FMCpwd), verify='/path/to/ssl_certificate')
        auth_headers = r.headers
        auth_token = auth_headers.get('X-auth-access-token', default=None)
        if auth_token == None:
            print("auth_token not found. Exiting...")
            sys.exit()
    except Exception as err:
        print ("Error in generating auth token --> "+str(err))
        sys.exit()
     
    headers['X-auth-access-token']=auth_token

def requesttofmc( api_path, params = None ):
    #Generic funciont to request objects to the fw
    #Returns the json response from the server
    url = FMCurl + api_path
    if (url[-1] == '/'):
        url = u)l[:-1]
    try:
        # REST call with SSL verification turned off: 
        if params != None:
            r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
        else:
            r = requests.get(url, headers=headers, verify=False)
        # REST call with SSL verification turned on:
        # r = requests.get(url, headers=headers, verify='/path/to/ssl_certificate')
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            print("GET successful. Response data --> ")
            json_resp = json.loads(resp)
            print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
        else:
            r.raise_for_status()
            print("Error occurred in GET --> "+resp)
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> "+str(err)) 
        finally:
            if r : r.close()
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err)) 
    finally:
        if r : r.close()

    return json_resp

def requestfwobjects( api_path ):
    #Request objects to the firewall and puts them to the 
    #list of added objects to avoid insertions of duplicate objects
    for item in requesttofmc( api_path )[ "items" ]:
        objectadded( item[ "name" ], item[ "type" ], item[ "id" ] )
    return result

def getfwhosts( domain ):
    #Gets all hostsdefined in the firewall
    api_path = "/api/fmc_config/v1/domain/" + domain + "/object/hosts" 
    return requestfwobjects ( api_path )

def getfwnetworkgroups( domain ):
    #Gets all network objects groups defined in the firewall
    api_path = "/api/fmc_config/v1/domain/" + domain + "/object/networkgroups"    # param
    return requestfwobjects ( api_path )

def getfwnetworks( domain ):
    #Gets all network objects defined in the firewall
    api_path = "/api/fmc_config/v1/domain/" + domain + "/object/networks"    # param
    return requestfwobjects ( api_path )

def getfwservices( domain ):
    #Gets all services defined in the firewall
    api_path = "/api/fmc_config/v1/domain/" + domain + "/object/protocolportobjects"    # param
    return requestfwobjects ( api_path )

def getfwzones( domain ):
    #Get firewall defined security zones
    api_path = "/api/fmc_config/v1/domain/" + domain + "/object/securityzones"
    return requestfwobjects ( api_path )

def getfwranges( domain ):
    #TODO:hight:
    pass

def getfwdomains():
    #TODO:low: Get a real list form de firewall
    #It seems with system information in metadata.domain.id?
    return [ defaultdomain ]

#TODO:hight: Get the rest of fw objects: applications, urls, etc...

def getfwdata():
    for domain in getfwdomains():
        getfwhosts( domain )
        getfwnetworkgroups( domain )
        getfwnetworks( domain )
        getfwzones( domain )

def isnetworktip( ipaddr ):
    """
    Checks if an ip address is a valid host IP
    @Returns: Boolean
    """
    #TODO:low: move it to the lib or parent class
    try
        netaddress = ipaddress.ip_interface( ipaddr )
        return True
    except ValueError as e:
        return False

def ishostip( ipaddr ):
    """
    Checks if an ip address is a valid host IP
    @Returns: Boolean
    """
    #TODO:low: move it to the lib or parent class
    try
        ipaddress.ip_address( unicode ( ipaddr ) )
        return True
    except ValueError as e:
        return False

def getelementtype( member ):
    """
    Generate the json code that references any existing object in the FMC
    If it is a literal returns False
    @Returns: json_code or False
    """
    membertype = False
    result = False 
    for elemtype, elem in addedelements:
        if member in elem:
            result = { "type" : '"' + elemtype + '"', "id" : '"' + elem[ member ], "name": '"' + member + '"' }
            if not membertype:
                #Stores the id and type of the member and continue checking
                membertype = elemtype
            else:
                #Find more than one member type with this name
                raise UserWarning( "getelementtype", "WARNING", "2 different objects type with same name: " + member + " of type " + membertype + " and " + elemtype + " can't get the correct reference" )
    return result

def getliteraltype( literal ):
    """
    Returns the json code of a literal element or False
    """
    if ishostip( literal ):
        return { "type" : "host", "value" : '"' + src + '"' }
    elif isnetworktip( literal ):
        return { "type" : "Network", "value" : '"' + src + '"' }
    return False

def getaclid( aclname, domain=defaultdomain ):
    """
    Returns the id of an ACL, if it is not in the addedelements list, 
    request the data to the FMC
    """

    if aclname not in addedelements[ "AccessPolicy" ]:
        json_resp = requesttofmc( "/api/fmc_config/v1/domain/" + domain + "/policy/accesspolicies" )
        for acl in json_resp[ "items" ] :
            if acl[ "name" ].lower() == aclname.lower():
                objectadded( aclname, "AccessPolicy", acl[ "id" ] )
                return acl[ "id" ]
    else:
        return addedelements[ "AccessPolicy" ][ aclname ]
    return False

def addhost ( csvline, domain=defaultdomain ):
    """
    Adds a host to the FMC
    """
    ip,name,description = csvline.split(",")

    post_data = {
      "type": "Host",
      "value": '"' + ip + '"',
      "overridable": "true",
      "description": '"' + description + '"',
      "name": '"' + name + '"'
    }

    api_path = "/api/fmc_config/v1/domain/" + domain + "/object/hosts"
    json_resp = requesttofmc( api_path, post_data )
    objectadded( json_resp [ "name" ], json_resp [ "type" ], json_resp [ "id" ] )
    return True

def addport( csvline, domain=defaultdomain ):
    """
    Adds a network port to the FMC
    """
    proto,port,name,description = csvline.split(",")

    post_data = { "type": "ProtocolPortObject" }

    try:
        #Checks if proto is a string and a known protocol
        socket.getprotobyname( proto )
    except:
        try:
            #Check if protocol is a number
            int( protocol ) + 1
        except:
            raise ValueError( "addport", "ERROR", "Unknown value: {value} for {field} in csv line: {line}".format( value=repr( proto ), field="protocol", line=repr( csvline ) ) )
    post_data[ "protocol" ] = proto
    try:
        portname = socket.getservbyname( port )
    except:
        try:
            portname = socket.getservbyport( port )
        except:
            raise ValueError( "addport", "ERROR", "Unknown value: {value} for {field} in csv line: {line}".format( value=repr( port ), field="port", line=repr( csvline ) ) )

    post_data[ "port" ] = port
    post_data[ "overridable" ] = "true"
    post_data[ "description" ] = description
    post_data[ "name" ] = name

    api_path = "/api/fmc_config/v1/domain/" + domain + "/object/protocolportobjects"
    json_resp = requesttofmc( api_path, post_data )
    objectadded( json_resp [ "name" ], json_resp [ "type" ], json_resp [ "id" ] )
    return True

def addportgroup( csvline, domain=defaultdomain ):
    """
    Adds a port object group to the FMC
    A group is filled with: Hosts, networks, or literals
    """
    name,members,description = csvline.split(",")

    if name in [ "" ]:
        raise ValueError( "addportgroup", "ERROR", "Invalid value: {value} for {field} in csv line: {line}".format( value=repr( name ), field="name", line=repr( csvline ) ) )

    post_data = { "type": "PortObjectGroup", "objects": [], "overridable": "true", "description": str( description ), "name": str( name ) }

    for member in members.split( " " ):
        memberdict = getelementtype( member )
        if not memberdict:
            raise ValueError( "addportgroup", "ERROR", "Invalid member {member} in group {group} for line: {csvlie}".format( member=repr( member ), group=repr( name ), line=repr( csvline ) ) )
        post_data[ "objects" ].append( memberdict )

    api_path = "/api/fmc_config/v1/domain/" + domain + "/object/networkgroups"
    json_resp = requesttofmc( api_path, post_data )
    objectadded( json_resp [ "name" ], json_resp [ "type" ], json_resp [ "id" ] )
    return True

def addnetwork( csvline, domain=defaultdomain ):
    """
    Adds a network to the FMC
    """
    ip,mask,name,description = csvline.split(",")º
    ip = ip + "/" + mask

    post_data = {
      "type": "Network",
      "value": '"' + ip + '"',
      "overridable": "true",
      "description": '"' + description + '"',
      "name": '"' + name + '"'
    }

    api_path = "/api/fmc_config/v1/domain/" + domain + "/object/networks"
    json_resp = requesttofmc( api_path, post_data )
    objectadded( json_resp [ "name" ], json_resp [ "type" ], json_resp [ "id" ] )
    return True

def addnetworkgroup ( csvline, domain=defaultdomain ):
    """
    Adds a network object group to the FMC
    A group is filled with: Hosts, networks, or literals
    """
    name,members,description = csvline.split(",")
    objects = []
    literals = []
    for member in members.split( " " ):
        try:
            ipaddress.ip_address( unicode ( host ) )
            #member is an ip address
            literals.append( { "type" : "host", "value" : '"' + host + '"' } ) 
        except ValueError as e:
            pass

        membertype = False
        for elemtype, elem in addedelements:
            if member in elem:
                objects.append( { "type" : '"' + elemtype + '"', "id" : '"' + elem[ member ], "name": '"' + member + '"' } )
                if not membertype:
                    #Stores the id and type of the member and continue checking
                    membertype = elemtype
                else:
                    #Find more than one member type with this name
                    print "ERROR: 2 different objects type with same name: " + member + " of type " + membertype + " and " + elemtype
                    exit( 3 )

    post_data={
        "type": "NetworkGroup"
        "objects": objects,
        "literals": literals,
        "overridable": true,
        "description": '"' + description + '"',
        "name": '"' + name + '"'
    }
    
    api_path = "/api/fmc_config/v1/domain/" + domain + "/object/networkgroups"
    json_resp = requesttofmc( api_path, post_data )
    objectadded( json_resp [ "name" ], json_resp [ "type" ], json_resp [ "id" ] )
    return True

def addiprange( csvline, domain=defaultdomain ):
    """
    Adds an IP range to the FMC
    """
    startip,endip,description = csvline.split(",")

    iprange = startip + "-" + endip
    post_data = {
      "type": "Range",
      "value": '"' + iprange + '"',
      "overridable": true,
      "description": '"' + description + '"',
      "name": '"' + name + '"'
    }

    api_path = "/api/fmc_config/v1/domain/" + domain + "/object/ranges"
    json_resp = requesttofmc( api_path, post_data )
    objectadded( json_resp [ "name" ], json_resp [ "type" ], json_resp [ "id" ] )
    return True

def addsecurityzone( csvline, domain=defaultdomain ):
    """
    Adds a security zone to the FMC
    """
    name,zonetype = csvline.split(",")

    if zonetype == "":
        interfacemode = "ROUTED"

    post_data = {
      "type": "SecurityZone",
      "name": '"' + name + '"'
      "interfaceMode": '"' + interfacemode + '"'
    }

    api_path = "/api/fmc_config/v1/domain/" + domain + "/object/securityzones"
    json_resp = requesttofmc( api_path, post_data )
    objectadded( json_resp [ "name" ], json_resp [ "type" ], json_resp [ "id" ] )
    return True

def addrule ( csvline, domain=defaultdomain ):
    """
    Adds a rule to the specified domain, the policy its defined as a field in the csv file
    """
    numfields = len( csvline.split( "," ) )
    if numfields != 12:
        raise ValueError( "addrule", "ERROR", "Invalid number of rows {rows} in rule {line}. There should be {length}: Action, Protocol, Sources, Source ports, Destinations, Destination ports, Log, Enable, Source zones, Destination zones, Rule name, ACL Name.".format( rows=repr( numfields ), line=repr( csvline ), length=repr( 12 ) ) )
    action,proto,source,srcport,destination,dstport,log,enabled,srczone,dstzone,name,aclname = csvline.split( "," )

    #Dictionary with the post data
    post_data = { "type": "AccessRule" }

    if action.lower() in [ "permit", "allow" ]:
        action == "ALLOW"
    elif action.lower() in [ "deny", "block" ]:
        action == "BLOCK"
    elif action.lower() in [ "reset", "block_reset" ]:
        action = "BLOCK_RESET"
    elif action.upper() in [ "TRUST", "MONITOR", "BLOCK_INTERACTIVE", "BLOCK_RESET_INT" ]:
        action = action.upper()
    else:
        raise ValueError( "addrule", "ERROR", "Unknown value: {value} for {field} in rule: {rule}".format( value=repr( action ), field="action", rule=repr( csvline) ) )
    post_data[ "action" ] = action
    
    #A rule can have more than one protocols
    protocols = []
    if proto.lower() == "tcpudp":
        protocols.append( socket.getprotobyname( "tcp" ) )
        protocols.append( socket.getprotobyname( "udp" ) )
    else:
        for protocol in proto.split(" ")
            try:
                #Try to get the protocol number as it was a string, if it fails, then try to use it as number
                protocols.append( socket.getprotobyname( protocol ) )
            except:
                try:
                    #Check if protocol is a number
                    int( protocol ) + 1
                    #Is it so adds it to the protocol list
                    protocols.append( protocol )
                except:
                    raise ValueError( "addrule", "ERROR", "Unknown value: {value} for {field} in rule: {rule}".format( value=repr( proto ), field="protocol", rule=repr( csvline ) ) )

    #Process source objects
    if source in [ "" ]:
        raise ValueError( "addrule", "ERROR", "Unknown value: {value} for {field} in rule: {rule}".format( value=repr( source ), field="source", rule=repr( csvline ) ) )
    else:
        #Create a list with the json for each element
        sourceslist = []
        sourceliteralslist = [] 
        for src in source.split(" "):
            json_code = getelementtype( src )
            if not json_code:
                #The object is not defined, so probably a literal
                literal = getliteraltype( src )
                if not literal:
                    raise ValueError( "addrule", "ERROR", "Invalid source object: {value} in rule: {rule}".format( value=repr( src ), rule=repr( csvline ) ) )
                sourceliteralslist.append( literal )
            sourceslist.append( json_code )

        if len( sourceliteralslist ) > 0:
            post_data[ "sourceNetworks" ][ "literals" ] = sourceliteralslist
        if len( sourceslist ) > 0:
            post_data[ "sourceNetworks" ][ "objects" ] = sourceslist

    #Process source port
    if str(srcport).lower() not in [ "any", "" ]:
        srcports = []
        srcportliterals = [] 
        for port in srcport.split(" "):
            json_code = getelementtype( port )
            for protocol in protocols:
                if not json_code:
                    #Port doesn't exists on the FMC, probably a literal
                    try:
                        int( port )
                        srcportliterals.append( { "type": "PortLiteral", "port": str( port ), "protocol": str( protocol ) } )
                    except:
                        raise ValueError( "addrule", "ERROR", "Invalid source port object: {value} in rule: {rule}".format( value=repr( port ), rule=repr( csvline ) ) )
            srcports.append( json_code )

        if len( srcportliterals ) > 0:
            post_data[ "sourcePorts" ][ "literals" ] = srcportliterals
        if len( srcports ) > 0:
            post_data[ "sourcePorts" ][ "objects" ] = srcports

    #Process destination objects
    if destination in [ "" ]:
        raise ValueError( "addrule", "ERROR", "Unknown value: {value} for {field} in rule: {rule}".format( value=repr( destination ), field="destination", rule=repr( csvline ) ) )
    else:
        #Create a list with the json for each element
        destinationlist = []
        destinationliteralslist = [] 
        for dst in destination.split(" "):
            json_code = getelementtype( dst )
            if not json_code:
                #The object is not defined, so probably a literal
                literal = getliteraltype( dst )
                if not literal:
                    raise ValueError( "addrule", "ERROR", "Invalid destination object: {value} in rule: {rule}".format( value=repr( dst ), rule=repr( csvline ) ) )
                destinationliteralslist.append( literal )
            destinationlist.append( json_code )

        if len( sourceliteralslist ) > 0:
            post_data[ "destinationNetworks" ][ "literals" ] = destinationliteralslist
        if len( sourceslist ) > 0:
            post_data[ "destinationNetworks" ][ "objects" ] = destinationlist

    #Process destination port
    if str(dstport).lower() not in [ "any", "" ]:
        dstports = []
        dstportliterals = [] 
        for port in dstport.split(" "):
            json_code = getelementtype( port )
            for protocol in protocols:
                if not json_code:
                    #Port doesn't exists on the FMC, probably a literal
                    try:
                        int( port )
                        dstportliterals.append( { "type": "PortLiteral", "port": str( port ), "protocol": str( protocol ) } )
                    except:
                        raise ValueError( "addrule", "ERROR", "Invalid destination port object: {value} in rule: {rule}".format( value=repr( port ), rule=repr( csvline ) ) )
            dstports.append( json_code )

        if len( dstportliterals ) > 0:
            post_data[ "destinationPorts" ][ "literals" ] = dstportliterals
        if len( dstports ) > 0:
            post_data[ "destinationPorts" ][ "objects" ] = dstports

    #Process log field
    if log.lower() in [ "yes", "true", "" ]:
        post_data[ "logEnd" ] = "true"
        post_data[ "sendEventsToFMC" ] = "true"
    elif log.lower() in [ "no", "false" ]:
        post_data[ "logEnd" ] = "false"
        post_data[ "sendEventsToFMC" ] = "false"
    else:
        raise ValueError( "addrule", "ERROR", "Unknown value: {value} for {field} in rule: {rule}".format( value=repr( log ), field="log", rule=repr( csvline ) ) )

    #Process enabled field
    if enabled.lower() in [ "yes", "enable", "active", "true", "" ]:
        post_data[ "enabled" ] = "true"
    elif enabled.lower() in [ "no", "disable", "inactive", "false" ]:
        post_data[ "enabled" ] = "false"
    else:
        raise ValueError( "addrule", "ERROR", "Unknown value: {value} for {field} in rule: {rule}".format( value=repr( enabled ), field="enabled", rule=repr( csvline ) ) )
    
    #Process source zones
    if srczone != "":
        srczones = { "objects": [] }
        for zone in srczone.split( " " ):
            srczones[ "objects" ].append( getelementtype( zone ) )
        post_data[ "sourceZones" ] = srczones

    #Process destination zones
    if dstzone != "":
        dstzones = { "objects": [] }
        for zone in dstzone.split( " " ):
            dstzones[ "objects" ].append( getelementtype( zone ) )
        post_data[ "destinationZones" ] = dstzones

    #Check that name is defined and not a reserved word
    if name.lower() in [ "" ]:
        raise ValueError( "addrule", "ERROR", "Unknown value: {value} for {field} in rule: {rule}".format( value=repr( name ), field="name", rule=repr( csvline ) ) )
    post_data[ "name" ] = name

    #Check that acl name is defined and not a reserved word
    if aclname.lower() in [ "" ]:
        raise ValueError( "addrule", "ERROR", "Unknown value: {value} for {field} in rule: {rule}".format( value=repr( aclname ), field="aclname", rule=repr( csvline ) ) )

    api_path = "/api/fmc_config/v1/domain/" + domain + "/policy/accesspolicies/" + getaclid( aclname ) + "/accessrules"
    json_resp = requesttofmc ( api_path, post_data )
    objectadded( "-".join( [ src,dst,dstport ] ) , json_resp [ "type" ], json_resp [ "id" ] )

    return True

def importhosts():
    print "Importing hosts"
    lines = getcsvlines( "hosts.csv" )
    count=0
    for line in lines:
        addhost( line )
        count += 1
    print "Hosts added: " + str( count )

def importnetworks()
    print "Importing network objects"
    lines = getcsvlines( "networks.csv" )
    count=0
    for line in lines:
        addnetwork( line )
        count += 1
    print "Networks added: " + str( count )

def importnetworkgroups():
    print "Importing network groups"
    lines = getcsvlines( "networkgroups.csv" )
    count=0
    for line in lines:
        addnetworkgroup( line )
        count += 1
    print "Network groups added: " + str( count )

def importipranges():
    #TODO:hight: addiprange not implemented
    print "Importing ip ranges, TODO: not implemented yet"
    return False
    objects = getcsvlines( "address-ranges.csv" )
    count=0
    for line in lines:
        addiprange( line )
        count += 1
    print "IP ranges added: " + str( count )

def importservices():
    print "Importing services"
    lines = getcsvlines( "services.csv" )
    count=0
    for line in lines:
        addport( line )
    print "Services added: " + str( count )

def importservicegroups():
    print "Importing service groups"
    lines = getcsvlines( "application-groups.csv" )
    count=0
    for line in lines:
        addportgroup( line )
    print "Service groups added: " + str( count )

def importacls():
    print "Importing access control policies"
    lines = getcsvlines( "acls.csv" )
    count=0
    for line in lines:
        addrule( line )
    print "ACLs added: " + str( count )

def importnat():
    print "Importing nat policies, not yet implemented"
    return False
    count=0
    for line in lines:
        #addnat( line )
        pass
    print "Nat policys added: " + str( count )

def main():
    try:
        auth()
        #importobjects()
        #importipranges()
        #importusers()
        #importservices()
        #importservicegroups()
        importnat()
        importacls()
        writeusedobjectstofile()
    except Exception as e:
        print e
        exit( 2 )
