rule signature_51
{
	meta:
		author = "0xlsd"
		sample = "66d9d7b6ca08171b1f5abf90db9108a8d37e8c219f88d5184f0fa08868a69f62"
	
	
	strings:
		$string_1 = {
			0F 01 0B
			01 05 ?? ?? ?? ??
			00 00
			10 00
			00 00
			80 00 00
			A0 ?? ?? ?? ??
			90
			00 00
			00 B0 ?? ?? ?? ??
			40
			00 00
			10 00
			00 00
		}
	
	condition:
		any of them
	
}
