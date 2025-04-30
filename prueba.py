import psycopg2
from datetime import datetime

# Conectar a la base de datos
conn = psycopg2.connect(
    host='127.0.0.1',
    port=5432,
    user='admin',
    password='admin',
    dbname='mib_browser'
)
cursor = conn.cursor()

# Datos del trap
trap_data = {
    'oid': '1.3.6.1.2.1.1.1.0',  # OID de ejemplo
    'value': 'Trap Test',  # Valor del trap
    'timestamp': datetime.now()  # Fecha y hora actual
}

# Insertar el trap
cursor.execute("""
    INSERT INTO notifications (oid, value, date_time) 
    VALUES (%s, %s, %s) RETURNING trap_id
""", (trap_data['oid'], trap_data['value'], trap_data['timestamp']))

trap_id = cursor.fetchone()[0]  # Obtener el ID del trap insertado
conn.commit()

print(f"Trap insertado con trap_id {trap_id}")

# Cerrar la conexión
cursor.close()
conn.close()
