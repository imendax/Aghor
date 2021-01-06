rule signature_116
{
	meta:
		author = "0xlsd"
		sample = "53cf5cf7e128f7ed7731685266823f3bc49098304dfbed936a5d6bc9397d6add"
	
	
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
			72 ??
			77 ??
			36 A3 ?? ?? ?? ??
		}
	
	condition:
		any of them
	
}
