#!/bin/bash
set -e  # stop on the first error

# Check the required environment variables
required_vars=(
  MONGO_INITDB_ROOT_USERNAME
  MONGO_INITDB_ROOT_PASSWORD
  MONGO_CUSTOMER_DATABASE
  MONGO_CUSTOMER_USERNAME
  MONGO_CUSTOMER_PASSWORD
  MONGO_PRODUCT_DATABASE
  MONGO_PRODUCT_USERNAME
  MONGO_PRODUCT_PASSWORD
)

for var in "${required_vars[@]}"; do
  if [ -z "${!var}" ]; then
    echo "ERROR: $var is not set"
    exit 1
  fi
done

# Create the users
mongosh -u "$MONGO_INITDB_ROOT_USERNAME" -p "$MONGO_INITDB_ROOT_PASSWORD" \
  --authenticationDatabase admin --quiet <<EOF
use $MONGO_CUSTOMER_DATABASE
db.createUser({
  user: "$MONGO_CUSTOMER_USERNAME",
  pwd: "$MONGO_CUSTOMER_PASSWORD",
  roles: [{ role: "readWrite", db: "$MONGO_CUSTOMER_DATABASE" }]
});

use $MONGO_PRODUCT_DATABASE
db.createUser({
  user: "$MONGO_PRODUCT_USERNAME",
  pwd: "$MONGO_PRODUCT_PASSWORD",
  roles: [{ role: "readWrite", db: "$MONGO_PRODUCT_DATABASE" }]
});
EOF

echo "Users created successfully"