#!/bin/sh

while psql -h postgres -U postgres -d postgres -c "select 1" > /dev/null 2>&1; do
  echo "Waiting for postgres server..."
  sleep 1
done

echo "Postgres started"

python3 app.py
