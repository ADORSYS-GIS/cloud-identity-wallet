#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

BASE_URL="http://localhost:8080"

echo -e "${YELLOW}Testing POST /api/v1/tenants endpoint${NC}\n"

# Test 1: Valid tenant creation
echo -e "${YELLOW}Test 1: Valid tenant creation${NC}"
response=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/v1/tenants" \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme Corporation"}')
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" -eq 201 ]; then
  echo -e "${GREEN}✓ PASS${NC} - Status: $http_code"
  echo "Response: $body"
else
  echo -e "${RED}✗ FAIL${NC} - Expected 201, got $http_code"
  echo "Response: $body"
fi
echo ""

# Test 2: Empty name
echo -e "${YELLOW}Test 2: Empty name (should return 400)${NC}"
response=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/v1/tenants" \
  -H "Content-Type: application/json" \
  -d '{"name": ""}')
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" -eq 400 ]; then
  echo -e "${GREEN}✓ PASS${NC} - Status: $http_code"
  echo "Response: $body"
else
  echo -e "${RED}✗ FAIL${NC} - Expected 400, got $http_code"
  echo "Response: $body"
fi
echo ""

# Test 3: Whitespace only name
echo -e "${YELLOW}Test 3: Whitespace only name (should return 400)${NC}"
response=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/v1/tenants" \
  -H "Content-Type: application/json" \
  -d '{"name": "   "}')
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" -eq 400 ]; then
  echo -e "${GREEN}✓ PASS${NC} - Status: $http_code"
  echo "Response: $body"
else
  echo -e "${RED}✗ FAIL${NC} - Expected 400, got $http_code"
  echo "Response: $body"
fi
echo ""

# Test 4: Name with 256 characters
echo -e "${YELLOW}Test 4: Name with 256 characters (should return 400)${NC}"
long_name=$(printf 'a%.0s' {1..256})
response=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/v1/tenants" \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"$long_name\"}")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" -eq 400 ]; then
  echo -e "${GREEN}✓ PASS${NC} - Status: $http_code"
  echo "Response: $body"
else
  echo -e "${RED}✗ FAIL${NC} - Expected 400, got $http_code"
  echo "Response: $body"
fi
echo ""

# Test 5: Name trimming
echo -e "${YELLOW}Test 5: Name trimming (whitespace should be removed)${NC}"
response=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/v1/tenants" \
  -H "Content-Type: application/json" \
  -d '{"name": "  Trimmed Name  "}')
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" -eq 201 ] && echo "$body" | grep -q '"name":"Trimmed Name"'; then
  echo -e "${GREEN}✓ PASS${NC} - Status: $http_code, name was trimmed"
  echo "Response: $body"
else
  echo -e "${RED}✗ FAIL${NC} - Expected 201 with trimmed name"
  echo "Response: $body"
fi
echo ""

# Test 6: Duplicate names produce different IDs
echo -e "${YELLOW}Test 6: Duplicate names produce different tenant_ids${NC}"
response1=$(curl -s -X POST "$BASE_URL/api/v1/tenants" \
  -H "Content-Type: application/json" \
  -d '{"name": "Duplicate Test"}')
id1=$(echo "$response1" | grep -o '"tenant_id":"[^"]*"' | cut -d'"' -f4)

response2=$(curl -s -X POST "$BASE_URL/api/v1/tenants" \
  -H "Content-Type: application/json" \
  -d '{"name": "Duplicate Test"}')
id2=$(echo "$response2" | grep -o '"tenant_id":"[^"]*"' | cut -d'"' -f4)

if [ "$id1" != "$id2" ] && [ -n "$id1" ] && [ -n "$id2" ]; then
  echo -e "${GREEN}✓ PASS${NC} - Different IDs generated"
  echo "ID 1: $id1"
  echo "ID 2: $id2"
else
  echo -e "${RED}✗ FAIL${NC} - IDs should be different"
  echo "ID 1: $id1"
  echo "ID 2: $id2"
fi
echo ""

echo -e "${YELLOW}All tests completed!${NC}"
