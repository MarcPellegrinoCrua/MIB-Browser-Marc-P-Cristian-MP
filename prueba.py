import psycopg2
import psycopg2.errors
import os

DB_CONFIG = {
    'host': '127.0.0.1',
    'port': 5432,
    'user': 'admin_mc',
    'password': 'admin',
    'dbname': 'mib_browser_mc'
}

def get_db_connection():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        print("Conexión a la base de datos exitosa.")
        return conn
    except psycopg2.errors.OperationalError as e:
        print(f"Error de conexión a la base de datos: {e}")
        raise

file_path = r'C:\Users\Onfir\Desktop\clase\python\MIB-Browser_Github\MIB-Browser\oids.txt'

def insert_oids():
    conn = None
    cursor = None
    inserted_count = 0

    try:
        if not os.path.exists(file_path):
            print(f"Error: Archivo no encontrado en la ruta especificada: {file_path}")
            return

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            with open(file_path, 'r', encoding='utf-16') as file:
                 lines = file.readlines()
            print("Archivo leído con codificación UTF-16.")
        except UnicodeDecodeError:
             print("UTF-16 falló. Intentando con UTF-16 Little Endian.")
             with open(file_path, 'r', encoding='utf-16-le') as file:
                 lines = file.readlines()
             print("Archivo leído con codificación UTF-16 LE.")
        except Exception as e:
             print(f"Error al leer el archivo con UTF-16 o UTF-16 LE: {e}")
             raise

        print(f"Intentando procesar {len(lines)} líneas del archivo '{os.path.basename(file_path)}'...")

        for i, line in enumerate(lines):
            original_line = line.rstrip('\r\n')
            processed_line = line.strip()

            if not processed_line:
                continue

            parts = processed_line.split()

            if len(parts) == 2:
                traduccio_oid_val = parts[0].strip().strip('"')
                oid_val = parts[1].strip().strip('"')

                if not oid_val or not traduccio_oid_val:
                     print(f"Advertencia: Saltando línea {i+1} ('{original_line}'): OID o traducción vacía después de separar/limpiar. OID='{oid_val}', Traducción='{traduccio_oid_val}'")
                     continue

                try:
                    cursor.execute("""
                        INSERT INTO oids (oid, traduccio_oid)
                        VALUES (%s, %s)
                    """, (oid_val, traduccio_oid_val))

                    inserted_count += 1

                except psycopg2.errors.UniqueViolation:
                    print(f"Advertencia: Saltando línea {i+1} ('{original_line}'): OID '{oid_val}' ya existe (violación de unicidad).")
                    conn.rollback()
                except psycopg2.errors.DataError as e:
                    print(f"Error de datos en línea {i+1} ('{original_line}'): No se pudo insertar el OID o traducción. Error: {e}")
                    conn.rollback()
                except psycopg2.Error as e:
                    print(f"Error de base de datos en línea {i+1} ('{original_line}'): Error: {e}")
                    conn.rollback()
                except Exception as e:
                     print(f"Error inesperado procesando línea {i+1} ('{original_line}'): {e}")
                     conn.rollback()


            else:
                print(f"Advertencia: Saltando línea {i+1} ('{original_line}'): Formato incorrecto. Se esperaban 2 partes separadas por tabulador, se encontraron {len(parts)}. Partes: {parts}")

        conn.commit()
        print("-" * 30)
        print(f"Proceso de inserción finalizado.")
        print(f"Total de líneas leídas del archivo: {len(lines)}")
        print(f"Total de OIDs que intentaron insertarse: {inserted_count}")
        print("Verifica la base de datos para confirmar los datos insertados.")

    except FileNotFoundError:
         print(f"Error: Archivo no encontrado (excepción): {file_path}")
    except psycopg2.errors.OperationalError:
        pass
    except Exception as e:
        print(f"Ocurrió un error inesperado durante el proceso principal: {e}")
        if conn:
            conn.rollback()
            print("Se realizó rollback de la transacción debido a un error principal.")

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
        print("-" * 30)


if __name__ == "__main__":
    insert_oids()