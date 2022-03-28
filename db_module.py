import sqlite3

def insert_query(query):
    connection, cursor = get_connection()
    cursor.execute(query)
    connection.commit()
    connection.close()
    return True


def select_query():
    pass


def update_query():
    pass


def get_connection():
    connection = sqlite3.connect("database.sqlite3")
    cursor = connection.cursor()
    return (connection, cursor)


def init_db():
    create_iocs_table = "CREATE TABLE iocs_for_cve (id INTEGER PRIMARY KEY AUTOINCREMENT," \
                        "cve_id TEXT NOT NULL, alien_vault_ioc_id TEXT NOT NULL, " \
                        "ioc_type TEXT NOT NULL, " \
                        "ioc_value TEXT NOT NULL, ioc_content TEXT NULL)"

    create_cve_table = "CREATE TABLE cve (cve_id TEXT NOT NULL)"

    insert_query(create_iocs_table)
    insert_query(create_cve_table)


def check_ioc_in_db(cve_id, alien_vault_ioc_id):
    connection, cursor = get_connection()
    query = "SELECT * FROM iocs_for_cve WHERE cve_id = '{}' AND alien_vault_ioc_id='{}'"
    cursor.execute(query.format(cve_id, alien_vault_ioc_id))
    data = cursor.fetchone()
    connection.close()
    if not data:
        return False
    else:
        return True