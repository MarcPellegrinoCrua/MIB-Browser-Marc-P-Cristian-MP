from flask import Flask, render_template, request
from pysnmp.hlapi import (
    getCmd, setCmd, nextCmd, bulkCmd,
    SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity,
    UsmUserData, usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol, usmDESPrivProtocol, usmAesCfb128Protocol, usmNoAuthProtocol, usmNoPrivProtocol
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

puerto = 162

DB_CONFIG = {
    'host': '127.0.0.1',
    'port': 5432,
    'user': 'admin_mc',
    'password': 'admin',
    'dbname': 'mib_browser_mc'
}

def get_db_connection():
    try:
        return psycopg2.connect(**DB_CONFIG)
    except psycopg2.OperationalError as e:
        print(f"Error al conectar con la base de datos: {e}")
        return None

@app.route("/", methods=["GET"])
def index():
    conn = get_db_connection()
    if conn is None:
        oid_list = []
        db_online = False
    else:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT oid, traduccio_oid FROM oids")
        oid_list = cursor.fetchall()
        cursor.close()
        conn.close()
        db_online = True
    return render_template("index.html", oid_list=oid_list, db_online=db_online)

@app.route("/snmp", methods=["POST"])
def snmp():
    try:
        agent_ip = request.form["agent_ip"]
        version = request.form["version"]
        oid = request.form["oid"]
        operation = request.form["operation"]
        set_value = request.form.get("set_value", "")
        set_type = request.form.get("set_type", "Integer")

        community = user = authkey = privkey = auth_protocol = priv_protocol = None

        if version in ['1', '2c']:
            community = request.form.get("community")
            if not community:
                return render_template("error.html", error_message="Falta el parámetro 'community'", error_detail="Obligatorio para SNMP v1/v2c.")
        elif version == '3':
            user = request.form.get('user')
            authkey = request.form.get('authkey')
            privkey = request.form.get('privkey')
            auth_protocol = request.form.get('auth_protocol')
            priv_protocol = request.form.get('priv_protocol')
            if not user:
                return render_template("error.html", error_message="Falta el usuario SNMPv3", error_detail="Debes rellenar el campo 'user' para SNMPv3.")

        if operation != "bulkwalk" and not oid.endswith(".0"):
            oid += ".0"

        if operation == "get":
            result = snmp_get(agent_ip, community, oid, version, user, authkey, privkey, auth_protocol, priv_protocol)
        elif operation == "next":
            result = snmp_next(agent_ip, community, oid, version, user, authkey, privkey, auth_protocol, priv_protocol)
        elif operation == "bulkwalk":
            result = snmp_bulkwalk(agent_ip, community, oid, version, user, authkey, privkey, auth_protocol, priv_protocol)
        elif operation == "set":
            if set_type == "OctetString":
                value = OctetString(set_value)
            else:
                try:
                    value = Integer(int(set_value))
                except ValueError:
                    return render_template("error.html", error_message="Valor incorrecte", error_detail="El valor no és vàlid per a Integer.")
            result = snmp_set(agent_ip, community, oid, value, version, user, authkey, privkey, auth_protocol, priv_protocol)
        else:
            return render_template("error.html", error_message="Operació no reconeguda", error_detail="L'operació SNMP no és vàlida.")

        return render_template(
            "result.html",
            result=result,
            agent_ip=agent_ip,
            version=version,
            community=community,
            oid=oid,
            operation=operation,
            user=user,
            authkey=authkey,
            privkey=privkey,
            auth_protocol=auth_protocol,
            priv_protocol=priv_protocol
        )
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

def get_auth_data(version, community=None, user=None, authkey=None, privkey=None, auth_protocol="NONE", priv_protocol="NONE"):
    if version in ['1', '2c']:
        mp_model = 0 if version == '1' else 1
        return CommunityData(community, mpModel=mp_model)
    elif version == '3':
        auth_proto_map = {
            'MD5': usmHMACMD5AuthProtocol,
            'SHA': usmHMACSHAAuthProtocol,
            'NONE': usmNoAuthProtocol
        }
        priv_proto_map = {
            'DES': usmDESPrivProtocol,
            'AES': usmAesCfb128Protocol,
            'NONE': usmNoPrivProtocol
        }

        auth_proto = auth_proto_map.get(auth_protocol.upper(), usmNoAuthProtocol)
        priv_proto = priv_proto_map.get(priv_protocol.upper(), usmNoPrivProtocol)

        if auth_protocol == "NONE":
            return UsmUserData(user)
        elif priv_protocol == "NONE":
            return UsmUserData(user, authkey, authProtocol=auth_proto, privProtocol=usmNoPrivProtocol)
        else:
            return UsmUserData(user, authkey, privkey, authProtocol=auth_proto, privProtocol=priv_proto)
    else:
        return None

def snmp_get(ip, community, oid, version, user=None, authkey=None, privkey=None, auth_protocol="NONE", priv_protocol="NONE"):
    result = []
    auth_data = get_auth_data(version, community, user, authkey, privkey, auth_protocol, priv_protocol)
    if not auth_data:
        result.append('Versión SNMP no soportada')
        return result

    iterator = getCmd(
        SnmpEngine(),
        auth_data,
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

def snmp_next(ip, community, oid, version, user=None, authkey=None, privkey=None, auth_protocol="NONE", priv_protocol="NONE"):
    result = []
    auth_data = get_auth_data(version, community, user, authkey, privkey, auth_protocol, priv_protocol)
    if not auth_data:
        result.append('Versión SNMP no soportada')
        return result

    iterator = nextCmd(
        SnmpEngine(),
        auth_data,
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

def snmp_bulkwalk(ip, community, oid, version, user=None, authkey=None, privkey=None, auth_protocol="NONE", priv_protocol="NONE"):
    result = []
    auth_data = get_auth_data(version, community, user, authkey, privkey, auth_protocol, priv_protocol)
    if not auth_data:
        result.append('Versión SNMP no soportada')
        return result

    iterator = bulkCmd(
        SnmpEngine(),
        auth_data,
        UdpTransportTarget((ip, 161)),
        ContextData(), 0, 1,
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False
    )

    for errorIndication, errorStatus, errorIndex, varBinds in iterator:
        if errorIndication:
            result.append(str(errorIndication))
            break
        elif errorStatus:
            result.append(f'{errorStatus.prettyPrint()} at {errorIndex}')
            break
        else:
            for varBind in varBinds:
                result.append(f'{varBind[0]} = {varBind[1]}')
    return result

def snmp_set(ip, community, oid, value, version, user=None, authkey=None, privkey=None, auth_protocol="NONE", priv_protocol="NONE"):
    result = []
    auth_data = get_auth_data(version, community, user, authkey, privkey, auth_protocol, priv_protocol)
    if not auth_data:
        result.append('Versión SNMP no soportada')
        return result

    iterator = setCmd(
        SnmpEngine(),
        auth_data,
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
    print("Trap recibido.")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        timestamp = datetime.now()

        protocolo = "udp"
        transport = str(f"{protocolo}:{puerto}")
        print(f"Transport usado: {transport}")

        main_oid = str(varBinds[0][0]) if varBinds else 'desconegut'
        main_value = str(varBinds[0][1]) if varBinds else 'desconegut'

        cursor.execute("""
            INSERT INTO notifications (oid, value, date_time, transport) 
            VALUES (%s, %s, %s, %s) RETURNING trap_id
        """, (main_oid, main_value, timestamp, transport))
        trap_id = cursor.fetchone()[0]
        print(f"Trap guardado con trap_id: {trap_id}")

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
        udp.UdpTransport().openServerMode(('0.0.0.0', puerto))
    )
    ntfrcv.NotificationReceiver(snmpEngine, trap_callback)
    print(f"Listener SNMP Trap iniciado en puerto {puerto}...")

    def dispatcher():
        snmpEngine.transportDispatcher.jobStarted(1)
        try:
            snmpEngine.transportDispatcher.runDispatcher()
        except Exception as e:
            snmpEngine.transportDispatcher.closeDispatcher()
            print(f"Error en listener: {e}")
            print(e)

    threading.Thread(target=dispatcher, daemon=True).start()

if __name__ == "__main__":
    trap_thread = threading.Thread(target=start_trap_listener, daemon=True)
    trap_thread.start()

    app.run(debug=True)