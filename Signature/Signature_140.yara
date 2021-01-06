rule signature_140
{
	meta:
		author = "0xlsd"
		sample = "dcae34a9c1350acc6a58dae3f00914f9ebe0cac6f395a2cdcad02135e7e2b918"
	
	
	strings:
		$string_1 = {
			6F
			63 2E
			63 72 ??
			61
			74 ??
			45
			6C
			65 6D
			65 6E
			74 ??
			22 73 ??
			72 ??
			70 ??
			22 29
			3B 0D ?? ?? ?? ??
			72 ??
			68 65 61 64 20
		}
	
	condition:
		any of them
	
}
