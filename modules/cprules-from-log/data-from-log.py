#!/usr/bin/python
import sys
import ipaddress

#sys.path.insert( 0, cfg.libdir ) )

internal_nets = { "10.100.25.0":"255.255.255.0", "10.1.11.0":"255.255.255.0", "172.26.0.0":"255.255.0.0", "192.168.125.0":"255.255.255.0", "192.168.240.0":"255.255.255.0", "192.168.25.0":"255.255.255.0", "192.168.252.0":"255.255.255.0", "192.168.254.0":"255.255.255.0", "192.168.255.0":"255.255.255.0", "192.168.30.0":"255.255.255.0", "192.168.75.0":"255.255.255.0" }

outputpath = "./output/"
filerules = "policies.csv"
fileapplications = "applications.csv"
fileobjects = "objects.csv"

inrules = []
outrules = []
applications = []
objects = []
cpservices = {}

historicpolicies = []
historicobjects = []
historicapplications = []

def loadhistoric ():
    for fname in [ filerules, fileobjects, fileapplications ]:
        f = open( outputpath + "historic-" + fname, "r" )
        i=0
        for line in f.readlines():
            if i == 0:
                i = 1
                #avoid to load the csv header
                continue
            if fname == filerules:
                historicpolicies.append( unicode( line.replace("\n", "") ) )
            elif fname == fileobjects:
                historicobjects.append( unicode( line.replace("\n", "") ) )
            else:
                historicapplications.append( unicode( line.replace("\n", "") ) )
        f.close()

def isdefined( obj, objtype ):
    #obj is a list, objtype a string
    if objtype == "policy":
        if not ",".join( obj[1:6] ) in historicpolicies:
            historicpolicies.append( ",".join( obj[1:6] ) )
            return False

    elif objtype == "object":
        if not ",".join( obj ) in historicobjects:
            historicobjects.append( ",".join( obj ) )
            return False

    elif objtype == "application":
        if not ",".join( obj ) in historicapplications:
            historicapplications.append( ",".join( obj ) )
            return False

    return True

def writecsv( filename, header, lines ):
    f = open( outputpath + filename, "w" )
    f.write( unicode( header + "\n" ) )
    for line in lines:
        f.write( unicode( line + "\n" ) )
    f.close()

def getcpservices ():
    f = open("cpservices.csv", "r")
    i=0
    cpservices["other_service"] = []
    cpservices["service_group"] = {}
    for line in f.readlines():
        if i==0:
            i+=1
            continue
        if len( line.split(",") ) == 4:
            name,proto,port,srcport = line.split(",")
            srcport = srcport.replace("\n","")
            cpservices[port+"/"+proto] = { "name":name, "srcport":srcport }
        elif len( line.split(",") ) == 2 :
            name,other = line.split(",")
            other = other.replace("\n","")
            if other == "other_service":
                cpservices["other_service"].append( name )

def getobjecttype ( obj ):
    if obj in internal_nets:
        return "net"
    else:
        return "host"

#def addrinnets( addr, net ):

def getspecialapplication( proto, port ):
    if proto == "icmp":
        return "icmp-proto"
    
    return False
    
def getconnections( logfile ):
    f = open( logfile, "r" )
    i=0
    action="accept"
    log="Log"
    disabled="true"
    for line in f.readlines():
        fields = line.split( "," )
        source = fields[2]
        destination = fields[3]
        srcport = fields[4]
        port = fields[5] 
        proto = fields[6]
        application = False
        
        direction = "incoming"
        if ipaddress.ip_address( unicode( source ) ).is_private:
            #Is an outgoing connection
            direction = "outgoing"


        name = direction + str(i)

        if getobjecttype( source ) == "net":
            obj = [ "ip", "impred_"+source, source, internal_nets[ source ], "" ]
            source = "impred_"+source
        else:
            obj = [ "ip", "imphost_"+source, source, "255.255.255.255", "" ]
            source = "imphost_"+source
        
        if not isdefined( obj, "object" ):
            objects.append( ",".join( obj ) )

        if getobjecttype( destination ) == "net":
            obj = [ "ip", "impred_"+destination, destination, internal_nets[ destination ], "" ]
            destination = "impred_"+destination
        else:
            obj = [ "ip", "imphost_"+destination, destination, "255.255.255.255", "" ]
            destination = "imphost_"+destination

        if not isdefined( obj, "object" ):
            objects.append( ",".join( obj ) )

        #Check if application is a service defined in checkpoint
        if port+"/"+proto in cpservices:
            if cpservices[ port+"/"+proto ]["srcport"] == "":
                #There is no src port so the service is defined in CP
                application = cpservices[ port+"/"+proto ]["name"]
            elif cpservices[ port+"/"+proto ]["srcport"] == srcport:
                #There is srcport and is the same as the rule
                #so the service is defined in CP
                application = cpservices[ port+"/"+proto ]["name"]
        else:
            application = getspecialapplication( proto, port )

        if not application:
            if not isdefined( [ proto + "_" + port, proto, "1-65535", port ], "application" ) :
                #The service is not defined in CP, we should add it
                applications.append( ",".join( [ proto + "_" + port, proto, "1-65535", port ] ) )
            application = proto + "_" + port
        
        rule = [ name,action,log,source,destination,application,disabled ]
        if not isdefined( rule, "policy" ) :
            if direction == "incoming":
                inrules.append( ",".join( rule ) )
            else:
                outrules.append( ",".join( rule ) )
            i += 1


    writecsv( fileobjects, "Type,Name,Address,Netmask,Description", objects )
    writecsv( "in-"+filerules, "Name,Action,Log,Source,Destination,Application,Disabled", inrules )
    writecsv( "out-"+filerules, "Name,Action,Log,Source,Destination,Application,Disabled", outrules )
    writecsv( fileapplications, "Name,Protocol,Srcport,Dstport", applications )

    writecsv( "historic-"+fileobjects, "Type,Name,Address,Netmask,Description", historicobjects )
    writecsv( "historic-"+filerules, "Action,Log,Source,Destination,Application,Disabled", historicpolicies )
    writecsv( "historic-"+fileapplications, "Name,Protocol,Srcport,Dstport", historicapplications )
    print "Objects added: " + str( len( objects ) )
    print "Applications added: " + str( len( applications ) )
    print "Policies added: " + str( len( inrules ) + len( outrules ) )

loadhistoric()
getcpservices()
getconnections( "rule-permit_all.csv" )
