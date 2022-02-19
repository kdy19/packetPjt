import sqlite3


def main():
    try:
        conn = sqlite3.connect('DB.db')
        print('[+] DB Create Success')
        try:
            conn.execute(
                'CREATE TABLE file_info (idx integer primary key,file_name text, file_hash text, upload_time text)'
            )
            conn.close()
            print('[+] Table Create Success')
        except Exception as e:
            print(e)
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()
