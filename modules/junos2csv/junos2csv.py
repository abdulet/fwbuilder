#!/usr/bin/python

#Import modules used
import xml.etree.ElementTree as ET
import re
import socket
import struct
from junosdecode import juniper_decrypt

#Variables to access to the input (xml) and output (csv) files 
path="."
dir_xml="xml"
dir_csv="../../csv"

def cidr_to_netmask(cidr):
    network, net_bits = cidr.split('/')
    host_bits = 32 - int(net_bits)
    netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
    return network, netmask

def checkunktags( tags, text ):
    """
    Search for unprocessed xml tags, the objective is to retrieve
    tags that are not beign expected to allow for its inclussion in the script
    tags: is a list of expected xml tags
    text: is the xml code in where search for new tags
    """
    alltags = []
    alltags = re.findall("<([^\/ >]+)", text)
    unktags = list(set(alltags) - set(tags))

    if len(unktags) > 0:
        #There is any unexpected tag so print an error and quit
        print "ERROR: Unknown tags finded:"
        print unktags
        quit()

def checkunkattr( attrs, text ):
    """
    Search for unprocessed tag attributes, the objective is to retrieve
    attribures that are not beign expected to allow for its inclussion in the script
    attrs: is a list of expected xml tag attributes
    text: is the xml code in where search for new tag attributes
    """
    allattrs = []
    allattrs = re.findall("([^\/ >]+)=", text)
    unkattr = list(set(allattrs) - set(attrs))

    if len(unkattr) > 0:
        #There is any unexpected attribute so print an error and quit
        print "ERROR: Unknown attributes detected"
        print unkattr
        quit()

def writecsv( objects, filename ):
    """
    Generates a csv files whith the given objects, the function get the path from the 
    global path variables and only expect the filename.
    objects: Is a list where each element is a new csv line to the file
    filename: Is the name of the csv file which is being generated
    """
    f = open(path+"/"+dir_csv+"/"+filename, "w")
    for line in objects:
        f.write( unicode(line) + "\n" )
    f.close()

def app2cp ( app ):
    ret=[]
    if app == "any-ip":
        ret.append("any")
    elif app == "junos-dns-tcp" or app == "junos-dns-udp" :
        ret.append("dns")
    elif app == "junos-icmp-all":
        ret.append("icmp-proto")
    elif app == "junos-icmp-ping" or app == "echo-request_1":
        ret.append("echo-request")
    elif app == "junos-ike" :
        ret.append("IKE")
    elif app == "junos-ike-nat" :
        ret.append("IKE_NAT_TRAVERSAL")
    elif app == "junos-nbds" :
        ret.append("nbdatagram")
    elif app == "junos-pop3" :
        ret.append("pop-3")
    elif app == "junos-printer":
        ret.append("lpdw0rm")
    elif app == "info-req":
        ret.append("info-req")
    elif app.find( "junos-" ) == 0:
        ret.append(app.replace( "junos-", "" ))
    elif app.find( "ESP" ) == 0:
        ret.append ( "esp" )
    elif app.find( "AH_1" ) == 0:
        ret.append ( "AH" )
    elif re.match( "^[0-9]", app ) != None:
        ret.append( "SRVC-" + app )
    else:
        ret.append( app )

    return ret


def policies2csv ():
    """
    Process the input xml file wich defines the rules of the fw,
    and generate the corresponding csv file
    """

    print "Parsing policies"
    #Used to define the status of each rule
    DISABLE="true"
    ENABLE="false"
    
    #Read the input xml file into an Elementree object
    tree = ET.parse(path+"/"+dir_xml+"/"+"policies.xml")
    policies = tree.getroot()

    #Define the list of xml tags which we expect to process
    knowntags = ["policies", "policy", "name", "match", "source-address", "destination-address", "then", "permit", "deny", "log", "session-init", "session-close", "ipsec-vpn", "tunnel", "application"]
    #knowntags = ["policies", "policy", "name", "match", "source-address", "destination-address", "then", "permit", "deny", "log", "session-init", "session-close", "application"]

    #Define the list of xml tag attributes which we expect to process
    knownattributes = ["inactive",]

    #Ensure that there is not any unexpected tag and attribute
    checkunktags( knowntags, ET.tostring(policies) )
    checkunkattr( knownattributes, ET.tostring(policies) )

    #Genearte the objects list to store the csv code,
    #the first line is the csv header
    objects = [ "Name,Action,Log,Source,Destination,Application,Disabled" ]

    #process each policy from the xml code and convert it to csv format 
    for policy in policies.findall("policy"):
        name = policy.find("name").text

        status=ENABLE
        if policy.get("inactive") == "inactive":
            status=DISABLE

        then=policy.find("then")
        action = ""
        if then.find("permit") != None:
            action = "accept"
        elif then.find("deny") != None:
            action = "deny"
        else:
            print "ERROR: policy without permit or deny, unknown action"
            print "Policy name: " + name
            print then.find("permit")
            quit()
        
        tracks="Log"
        if then.find("log") == None:
            tracks="None"
        
        match = policy.find("match")
        source = []
        for src in match.findall("source-address"):
            source.append( src.text.lower() )
        
        if len(source) == 0:
            print "ERROR: Policy without source, or not well detected"
            print "Policy name: " + name
            print match.findall("source-address")
            quit()

        destination = []
        for dst in match.findall("destination-address"):
            destination.append( dst.text.lower() )

        if len(source) == 0:
            print "ERROR: Policy without destination, or not well detected"
            print "Policy name: " + name
            print match.findall("destination-address")
            quit()
        
        application = []
        for app in match.findall("application"):
            application += app2cp ( app.text )
        
        if len(application) == 0:
            print "ERROR: Policy without services, or not well detected"
            print "Policy name: " + name
            print match.findall("application")
            quit()

        #Insert the csv code to the objects list
        objects.append( name+"," + action+"," + tracks+"," + " ".join(source)+"," + " ".join(destination) + "," + " ".join(application) + "," + status )

    #Fills csv file with objects in lines list
    writecsv(objects, "policies.csv") 
    print " Policies retrieved: " + str( len(objects)-1 )
    return 0
    #TODO: Mirar si junos soporta comentaris i a on son

def objects2csv():
    """
    Process the input xml file wich defines the objects used by
    the policy rules of the fw, and generate the corresponding csv file
    """

    print "Parsing objects"
    
    #Read the input xml file into an Elementree object
    tree = ET.parse( path + "/" + dir_xml + "/" + "zones.xml" )
    root = tree.getroot()

    #Define the list of xml tags which we expect to process
    knowntags = [ "zones", "functional-zone", "management", "host-inbound-traffic", "system-services", "security-zone", "address-book", "screen", "address", "address-set", "name", "description", "ip-prefix", "interfaces", "protocols", "dns-name"]

    #Define the list of xml tag attributes which we expect to process
    knownattributes = []

    #Ensure that there is not any unexpected tag and attribute
    checkunktags( knowntags, ET.tostring(root) )
    checkunkattr( knownattributes, ET.tostring(root) )

    zones = root.findall( "security-zone" )
    objects = [ "Type,Name,Address,Netmask,Description" ]
    for zone in zones:
        addressbook = zone.find( "address-book" )
        for address in addressbook.findall( "address" ):
            description = address.find( "description" )
            if description == None:
                description = ""
            else:
                description = description.text

            ipaddr = address.find( "ip-prefix" )
            name = address.find("name").text
            if ipaddr != None:
                ip,mask = cidr_to_netmask( ipaddr.text )
                insline = "ip," + name.lower() + "," + ip + "," + mask + "," + description
                if insline not in objects:
                    objects.append( insline )
            elif address.find( "dns-name" ) != None:
                url = address.find( "dns-name" ).find( "name" ).text
                insline = "url," + name.lower() + "," + url + ",," + description
                if insline not in objects:
                    objects.append( insline )

        for addressset in addressbook.findall("address-set"):
            name = addressset.find("name").text
            addresses = []
            for address in addressset.findall("address"):
                addresses.append( address.find("name").text.lower()  )
            insline = "group," + name.lower() + "," + " ".join(addresses) + ",,"
            if insline not in objects:
                objects.append( insline )

    writecsv( objects, "objects.csv" )
    print " Objects retrieved: " + str( len(objects)-1 )

def users2csv():
    """
    Process the input xml file wich defines the users and groups of the fw,
    and generate the corresponding csv file
    """

    print "Parsing users"
    #Read the input xml file into an Elementree object
    tree = ET.parse(path+"/"+dir_xml+"/"+"users.xml")
    root = tree.getroot()

    #Define the list of xml tags which we expect to process
    knowntags = ["access", "profile", "name", "authentication-order", "client", "firewall-user", "password", "address-assignment", "pool", "family", "inet", "network", "range", "low", "high", "xauth-attributes", "primary-dns", "secondary-dns", "chap-secret", "default-profile", "firewall-authentication", "web-authentication" ]

    #Define the list of xml tag attributes which we expect to process
    knownattributes = []

    #Ensure that there is not any unexpected tag and attribute
    checkunktags( knowntags, ET.tostring(root) )
    checkunkattr( knownattributes, ET.tostring(root) )

    profiles = root.findall("profile")
    objects = [ "Username,Password" ]
    for profile in profiles:
        for user in profile.findall("client"):
            username=user.find( "name" ).text or ""
            password = user.find( "firewall-user" ).find( "password" ).text or ""
            if password.find("$9") == 0:
                password=juniper_decrypt( password )
            
            chap = user.find("chap-secret")
            if chap != None:
                chap = chap.text
                print "Chap property not implemented yet, check import of user " + username
            #else:
            #    chap=""

            objects.append( username + "," + password )
    writecsv( objects, "users.csv" )
    print " Users retrieved: " + str( len(objects)-1 )
    objects = [ "Poolname,Netip,Nemask,RangeName,Starip,Endip,DNS1,DNS2" ]
    for pool in root.find("address-assignment").findall( "pool" ):
        name = pool.find( "name" ).text
        inet = pool.find( "family" ).find( "inet" )
        netip,netmask = cidr_to_netmask( inet.find( "network" ).text )
        rng = inet.find( "range" )
        rngname = rng.find( "name" ).text
        startip = rng.find( "low" ).text
        endip = rng.find( "high" ).text
        dns1 = inet.find( "xauth-attributes" ).find( "primary-dns" ).text
        dns2 = inet.find( "xauth-attributes" ).find( "secondary-dns" ).text
        objects.append( name + "," + netip + "," + netmask + "," + rngname + "," + startip + "," + endip + "," + dns1 + "," + dns2 )
    writecsv( objects, "pools.csv" )
    print " Pools retrieved: " + str( len(objects)-1 )

def apps2csv():
    print "Parsing apps"
    #Read the input xml file into an Elementree object
    tree = ET.parse(path+"/"+dir_xml+"/"+"applications.xml")
    root = tree.getroot()

    #Define the list of xml tags which we expect to process
    knowntags = [ "applications", "application", "name", "protocol", "source-port", "destination-port", "icmp-type", "term", "application-set" ]

    #Define the list of xml tag attributes which we expect to process
    knownattributes = []

    with open( path + "/excluded-services.txt", "r" ) as f:
        excludedservices = f.read().lower().split( "\n" )
        excludedservices.append ( "netbios-ssn" )

    #Ensure that there is not any unexpected tag and attribute
    checkunktags( knowntags, ET.tostring(root) )
    checkunkattr( knownattributes, ET.tostring(root) )

    lines=[ "Name,Protocol,Srcport,Dstport" ]
    groups = [ "Name,Applications" ]
    for app in root.findall( "application" ):
        name = app.find( "name" ).text
        if name.lower() in excludedservices:
            print "Attention excluded service " + name
            continue

        if name.find( "junos-" ) == 0 or name == "echo-request_1" or name == "info-req" :
            continue

        if app.find( "term" ) == None:
            protocol = app.find( "protocol" ).text
            srcport = app.find( "source-port" ).text
            dstport = app.find( "destination-port" ).text
            lines.append( app2cp ( name )[0] + "," + protocol + "," + srcport + "," + dstport)
        else:
            i=0
            groupapps = []
            for term in app.findall( "term" ):
                subname = name + "-" + str(i)
                protocol = term.find( "protocol" ).text
                srcport = term.find( "source-port" ).text
                dstport = term.find( "destination-port" ).text
                lines.append( app2cp( subname )[0] + "," + protocol + "," + srcport + "," + dstport)
                groupapps.append( subname )
                i += 1
            groups.append( name + "," + " ".join( groupapps ) )
    
    writecsv( lines, "applications.csv" )
    print " Applications retrieved: " + str( len( lines )-1 )

    for group in root.findall( "application-set" ):
        name = group.find( "name" ).text
        if name.lower() in excludedservices:
            print "Attention excluded service " + name
            continue
        
        apps = []
        for app in group.findall( "application" ):
            apps += app2cp( app.find( "name" ).text )
        
        groups.append( name + "," + " ".join( apps ) )

    writecsv ( groups, "application-groups.csv" )
    print " Application groups retrieved: " + str( len( groups )-1 )

def nat2csv():
    print "NAT import not yet implemented!!!"

policies2csv()
objects2csv()
users2csv()
nat2csv()
apps2csv()
