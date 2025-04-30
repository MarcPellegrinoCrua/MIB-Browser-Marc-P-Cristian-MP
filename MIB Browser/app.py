from flask import Flask, render_template, request
from pysnmp.hlapi import (
    getCmd, setCmd, nextCmd, bulkCmd,
    SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity
)
from pysnmp.proto.rfc1902 import OctetString, Integer
from pysnmp.error import PySnmpError
import socket
import psycopg2
from datetime import datetime

app = Flask(__name__)

# Database configuration - replace with your credentials
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'user': 'admin',
    'password': 'admin',
    'dbname': 'mib_browser'
}

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

@app.route("/", methods=["GET"])
def index():
    # Fetch OIDs for dropdown
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT oid, traduccio_oid FROM oids")
    oid_list = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("index.html", oid_list=oid_list)

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

@app.route("/traps", methods=["GET"])
def show_traps():
    # filter parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT trap_id, date_time, transport FROM notifications"
    params = []
    if start_date and end_date:
        query += " WHERE date_time BETWEEN %s AND %s"
        params = [start_date + ' 00:00:00', end_date + ' 23:59:59']
    elif start_date:
        query += " WHERE DATE(date_time) = %s"
        params = [start_date]
    cursor.execute(query, params)
    traps = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("traps.html", traps=traps, start_date=start_date, end_date=end_date)

@app.route("/traps/<int:trap_id>", methods=["GET"])
def trap_details(trap_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT oid, value FROM varbinds WHERE trap_id = %s", (trap_id,))
    varbinds = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("trap_details.html", trap_id=trap_id, varbinds=varbinds)

# SNMP helper functions unchanged...

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
        lexicographicMode=False
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
