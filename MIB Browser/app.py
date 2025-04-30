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
import threading

from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import ntfrcv

app = Flask(__name__)

DB_CONFIG = {
    'host': '127.0.0.1',
    'port': 5432,
    'user': 'admin',
    'password': 'admin',
    'dbname': 'mib_browser'
}

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

@app.route("/", methods=["GET"])
def index():
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
def trap_callback(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    print("Trap recibido.")  # Este mensaje debería imprimirse cuando el trap es recibido.
    try:
        # Conexión a la base de datos
        conn = get_db_connection()
        cursor = conn.cursor()

        timestamp = datetime.now()

        # Por defecto, toma el primer varbind como 'principal'
        main_oid = str(varBinds[0][0]) if varBinds else 'desconegut'
        main_value = str(varBinds[0][1]) if varBinds else 'desconegut'

        # Insertar en la tabla notifications (ahora con oid y value)
        cursor.execute("""
            INSERT INTO notifications (oid, value, date_time) 
            VALUES (%s, %s, %s) RETURNING trap_id
        """, (main_oid, main_value, timestamp))
        trap_id = cursor.fetchone()[0]
        print(f"Trap guardado con trap_id: {trap_id}")

        # Insertar cada varbind en la tabla varbinds
        for oid, value in varBinds:
            cursor.execute("""
                INSERT INTO varbinds (trap_id, oid, value) 
                VALUES (%s, %s, %s)
            """, (trap_id, str(oid), str(value)))
            print(f"Varbind guardado: OID = {oid}, Value = {value}")

        conn.commit()
        cursor.close()
        conn.close()

    except Exception as e:
        print(f"Error al insertar el trap en la base de datos: {e}")

def start_trap_listener():
    snmpEngine = engine.SnmpEngine()
    config.addV1System(snmpEngine, 'my-area', 'public_mp')
    config.addTransport(
        snmpEngine,
        udp.domainName,
        udp.UdpTransport().openServerMode(('0.0.0.0', 162))
    )
    ntfrcv.NotificationReceiver(snmpEngine, trap_callback)
    print("Listener SNMP Trap iniciado en puerto 162...")  # Asegúrate de que esto se imprima

    def dispatcher():
        snmpEngine.transportDispatcher.jobStarted(1)
        try:
            snmpEngine.transportDispatcher.runDispatcher()
        except Exception as e:
            snmpEngine.transportDispatcher.closeDispatcher()
            print(f"Error en listener: {e}")
            print(e)  # Agregar un mensaje de error para depuración

    threading.Thread(target=dispatcher, daemon=True).start()

if __name__ == "__main__":
    trap_thread = threading.Thread(target=start_trap_listener, daemon=True)
    trap_thread.start()

    app.run(debug=True)