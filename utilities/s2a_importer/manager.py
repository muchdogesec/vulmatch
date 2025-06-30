
import sqlite3
import atexit

class VersionManager:
    def __init__(self, db_name, table_name):
        self.db_name = db_name
        self.table_name = table_name
        
        # Connect to the SQLite database
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        
        # Create the versions table if it does not exist
        self.create_table()
        atexit.register(self.close)
    
    def create_table(self):
        # Create the table with an additional 'reason' column if it does not exist
        self.cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {self.table_name} (
                version TEXT PRIMARY KEY,
                failed BOOLEAN DEFAULT 0,
                reason TEXT
            )
        ''')
        self.conn.commit()
    
    def set_failed(self, version, failed=True, reason=None):
        # Insert or update the version in the database, including the reason for failure
        self.cursor.execute(f'''
            INSERT INTO {self.table_name} (version, failed, reason)
            VALUES (?, ?, ?)
            ON CONFLICT(version) 
            DO UPDATE SET failed = ?, reason = ?
        ''', (version, failed, reason, failed, reason))
        self.conn.commit()
    
    def remove_version(self, version):
        # Remove a version from the database once it's done
        self.cursor.execute(f'''
            DELETE FROM {self.table_name}
            WHERE version = ?
        ''', (version,))
        self.conn.commit()

    def get_versions(self, failed=None):
        # Get versions, filter by failed status if provided
        if failed is None:
            self.cursor.execute(f'SELECT version, failed FROM {self.table_name}')
        else:
            self.cursor.execute(f'''
                SELECT version, failed FROM {self.table_name}
                WHERE failed = ?
            ''', (failed,))
        
        return {version: failed for version, failed in self.cursor.fetchall()}

    def close(self):
        # Close the database connection
        print(f'closing {self.db_name}...')
        self.conn.close()

    def recreate_table(self):
        print('recreating tables')
        # Delete the table and recreate it
        self.cursor.execute(f'DROP TABLE IF EXISTS {self.table_name}')
        self.create_table()