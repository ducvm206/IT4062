## Import thu vien
sudo apt update
sudo apt install libmariadb-dev
sudo apt install libgtk-3-dev

## Chay chuong trinh

1. Make
make clean && make

2. Copy binary client vao clientA va clientB:
cp client/client clientA/
cp client/client clientB/

3. Chay server:
cd server && ./server

4. Chay client
cd clientA && ./client
cd clientB && ./client

## Xem DB
1. Mo MariaDB
mysql -u p2puser -p p2p_db
Go password: p2ppass

2. SELECT * FROM <ten bang>;



