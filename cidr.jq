def _cidr_addr: .|split("/")|.[0];

def _cidr_pton: 
	[_cidr_addr|split(".")+["0","0","0","0"]|.[0,1,2,3]|tonumber]|(.[0]*16777216)
	+(.[1]*65536)+(.[2]*256)+.[3];

def _cidr_ntop:
	. as $n|[($n%256)]|.+[(($n-.[0])%65536)/256]
	|.+[(($n-.[0]-.[1])%16777216)/65536|floor]
	|.+[($n-.[0]-.[1]-.[2])/16777216|floor]|map(tostring)|reverse|join(".");

def _cidr_net: .|split("/")+["32"]|.[1];

def _cidr_net_pton: _cidr_net|tonumber;

def _cidr_net_ntop($b): .-(.%pow(2;32-$b))|_cidr_ntop+"/"+($b|tostring);

def _cidr_mask: (pow(2;32)-1)-(pow(2;32-.)-1)|_cidr_ntop;

def cidr($in): $in|_cidr_net_pton as $b|($in|_cidr_pton) as $a
	|(if ($b==32) then 1 else (if $b==31 then 2 else (pow(2;32-$b)-2) end) end) as $s
	|($a-($a%pow(2;32-$b))) as $n|{
	address: ($a|_cidr_ntop),
	netmask: ($b|_cidr_mask),
	prefix: $b,
	broadcast: (if ($b<31) then ($n+$s+1|_cidr_ntop) else (if $s==2 then (32|_cidr_mask) else ($n|_cidr_ntop) end) end),
	network: ($n|_cidr_ntop),
	minaddr: (if ($b<31) then ($n+1|_cidr_ntop) else ($n|_cidr_ntop) end),
	maxaddr: (if ($b<31) then ($n+$s|_cidr_ntop) else if ($s==2) then ($n+1|_cidr_ntop) else ($n|_cidr_ntop) end end),
	addresses: $s,
	cidr: ($a|_cidr_net_ntop($b))
};

def _iscidr: ((.|type=="string") and (.|contains(".")));

def _tocidr: (if ((.|type)=="string" and (.|_iscidr)) then (cidr(.)) else 
	(if ((.|type)=="object" and .cidr? and .network? and .prefix?) 
		then . else error("Not a valid network address")
	end)
end);

def _tocidr($bits): .|_tocidr.network|_cidr_pton|_cidr_net_ntop($bits)|_tocidr;

def _cidr_range: . as $n|($n.network|_cidr_pton) as $min
	|($min+pow(2;32-($n.prefix))-1) as $max|[$min,$max];

def inside_cidr($a): (cidr($a)|_cidr_range) as $ir
	|_tocidr|_cidr_range as $r|($r[0] >= $ir[0] and $r[1] <= $ir[1]);

def contains_cidr($a): (cidr($a)|_cidr_range) as $r
	|_tocidr|_cidr_range as $ir|($r[0] >= $ir[0] and $r[1] <= $ir[1]);

def _cidr_addrspace: (if inside_cidr("0/8") then "software"
		elif inside_cidr("127/8") then "loopback"
		elif inside_cidr("10/8") or inside_cidr("172.16/12") or inside_cidr("192.168/16") or inside_cidr("198.18/15") then "private"
		elif inside_cidr("169.254/16") then "link-local"
		elif inside_cidr("224/4") then "multicast"
		elif inside_cidr("240/4") then "reserved"
		elif inside_cidr("255.255.255.255/32") then "broadcast"
		else "internet"
	end);

def is_private: _cidr_addrspace=="private";

def is_internet: _cidr_addrspace=="internet";

def is_loopback: _cidr_addrspace=="loopback";

def tocidr: _tocidr + {"addrspace": _cidr_addrspace};

def tocidr($bits): _tocidr($bits) + {"addrspace": _cidr_addrspace};
