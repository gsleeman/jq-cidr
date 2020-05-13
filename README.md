# jq-cidr
CIDR module for jq

## Examples

### Basic usage

#### Input
```json
{"net": "8.8.8.0/28"}
{"net": "192.168.24.128/28"}
{"net": "1.1.1.1"}
```

```bash
jq '.net|tocidr'
```

#### Output
```json
{
  "address": "8.8.8.0",
  "netmask": "255.255.255.240",
  "prefix": 28,
  "broadcast": "8.8.8.15",
  "network": "8.8.8.0",
  "range": ["8.8.8.1", "8.8.8.14"],
  "addresses": 14,
  "cidr": "8.8.8.0/28",
  "addrspace": "internet"
}
{
  "address": "192.168.24.128",
  "netmask": "255.255.255.240",
  "prefix": 28,
  "broadcast": "192.168.24.143",
  "network": "192.168.24.128",
  "range": ["192.168.24.129", "192.168.24.142"],
  "addresses": 14,
  "cidr": "192.168.24.128/28",
  "addrspace": "private"
}
{
  "address": "1.1.1.1",
  "netmask": "255.255.255.255",
  "prefix": 32,
  "network": "1.1.1.1",
  "addresses": 1,
  "cidr": "1.1.1.1/32",
  "addrspace": "internet"
}
```

### Network intersection

```bash
echo '"192.168.24.128/28"' | jq 'contains_cidr("192.168.24.132/30")'
true
```

```bash
jq '"192.168.24.1"' | jq 'inside_cidr("192.168.24.0/24")' 
true
```

### Address space helpers

```bash
echo '"192.168.24.128"' | jq 'is_private'
true
echo '"1.1.1.1"' | jq 'is_internet'
true
```


