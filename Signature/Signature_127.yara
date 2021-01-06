rule signature_127
{
	meta:
		author = "0xlsd"
		sample = "dc84487096537177a5ad1a89f94773548ce535fdd83584a73688c8172c43fb1a"
	
	
	strings:
		$string_1 = {
			01 AD ?? ?? ?? ??
			60
			28 EB
			96
			62 6C 8D ??
			0D AC 61 09 F9
			E6 C0
			85 24 51
			FB
			AB
			50
			ED
			2E DA 52 ??
			FD
			DE CB
			55
			2E 9D
			87 F2
		}
	
	condition:
		any of them
	
}
