rule signature_70
{
	meta:
		author = "0xlsd"
		sample = "9669782b3501cdcb1a72eea781a12bde97e23f60e0750f390d8c931142fed00d"
	
	
	strings:
		$string_1 = {
			20 72 ??
			6E
			20 69 ??
			20 44 4F ??
			20 6D ??
			64 65 2E 0D 0D 0A 24 00
			00 00
			00 00
			00 00
			24 98
			14 9B
			60
			F9
			7A ??
			60
			F9
			7A ??
		}
	
	condition:
		any of them
	
}
