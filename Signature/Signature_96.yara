rule signature_96
{
	meta:
		author = "0xlsd"
		sample = "4d647266dae7cfd337b11c827f8da2fc9cc32f1ecaef1a7982c7f3c358563a61"
	
	
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
			4F
			AD
			A0 ?? ?? ?? ??
			88 0B
			CC
			CE
		}
	
	condition:
		any of them
	
}
