from flask import Flask, render_template, request
from pysnmp.hlapi import (
    getCmd, setCmd, nextCmd, bulkCmd,
    SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity
)
from pysnmp.proto.rfc1902 import OctetString, Integer
from pysnmp.error import PySnmpError
import socket

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/snmp", methods=["POST"])
def snmp():
    try:
        agent_ip = request.form["agent_ip"]
        version = request.form["version"]
        community = request.form["community"]
        oid = request.form["oid"]
        operation = request.form["operation"]
        set_value = request.form.get("set_value", "")
        set_type = request.form.get("set_type", "Integer")

        if operation != "bulkwalk" and not oid.endswith(".0"):
            oid += ".0"
        if operation == "get":
            result = snmp_get(agent_ip, community, oid)
        elif operation == "next":
            result = snmp_next(agent_ip, community, oid)
        elif operation == "bulkwalk":
            result = snmp_bulkwalk(agent_ip, community, oid)
        elif operation == "set":
            if set_type == "OctetString":
                value = OctetString(set_value)
            else:
                try:
                    value = Integer(int(set_value))
                except ValueError:
                    return render_template("error.html", error_message="Valor incorrecte", error_detail="El valor no és vàlid per a Integer.")
            result = snmp_set(agent_ip, community, oid, value)
        return render_template("result.html", result=result, agent_ip=agent_ip, version=version, community=community, oid=oid, operation=operation)

    except (PySnmpError, socket.gaierror) as e:
        return render_template("error.html", error_message="Error SNMP o de xarxa", error_detail=str(e))

def snmp_get(ip, community, oid):
    result = []
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication:
        result.append(str(errorIndication))
    elif errorStatus:
        result.append(f'{errorStatus.prettyPrint()} at {errorIndex}')
    else:
        for varBind in varBinds:
            result.append(f'{varBind[0]} = {varBind[1]}')
    return result

def snmp_next(ip, community, oid):
    result = []
    iterator = nextCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication:
        result.append(str(errorIndication))
    elif errorStatus:
        result.append(f'{errorStatus.prettyPrint()} at {errorIndex}')
    else:
        for varBind in varBinds:
            result.append(f'{varBind[0]} = {varBind[1]}')
    return result

def snmp_bulkwalk(ip, community, oid):
    result = []
    iterator = bulkCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, 161)),
        ContextData(), 0, 1,
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode = False
    )
    for (errorIndication, errorStatus, errorIndex, varBinds) in iterator:
        if errorIndication:
            result.append(str(errorIndication))
            break
        elif errorStatus:
            result.append(f'{errorStatus.prettyPrint()} at {errorIndex}')
            break
        else:
            for varBind in varBinds:
                result.append(f'{varBind[0]} = {varBind[1].prettyPrint()}')
    return result

def snmp_set(ip, community, oid, value):
    result = []
    iterator = setCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid), value)
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication:
        result.append(str(errorIndication))
    elif errorStatus:
        result.append(f'{errorStatus.prettyPrint()} at {errorIndex}')
    else:
        for varBind in varBinds:
            result.append(f'{varBind[0]} = {varBind[1]}')
    return result

if __name__ == "__main__":
    app.run(debug=True)
