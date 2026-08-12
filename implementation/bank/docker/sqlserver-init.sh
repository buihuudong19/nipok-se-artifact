#!/bin/bash
set -e

# Start SQL Server in background
/opt/mssql/bin/sqlservr &
MSSQL_PID=$!

SQLCMD="/opt/mssql-tools18/bin/sqlcmd -No"

echo "Waiting for SQL Server to be ready..."
for i in $(seq 1 60); do
    if $SQLCMD -S localhost -U sa -P "$MSSQL_SA_PASSWORD" -Q "SELECT 1" > /dev/null 2>&1; then
        echo "SQL Server is ready after ${i} attempts"
        break
    fi
    sleep 2
done

echo "Creating database if not exists..."
$SQLCMD -S localhost -U sa -P "$MSSQL_SA_PASSWORD" -Q "
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'transaction-db')
    CREATE DATABASE [transaction-db]
GO"

echo "Disabling AUTO_CLOSE on transaction-db..."
$SQLCMD -S localhost -U sa -P "$MSSQL_SA_PASSWORD" -Q "
ALTER DATABASE [transaction-db] SET AUTO_CLOSE OFF
GO"

echo "SQL Server initialization complete"

wait $MSSQL_PID
