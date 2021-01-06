rule signature_31
{
	meta:
		author = "0xlsd"
		sample = "9566f7a74489a6937ad72dd633a0c96c5b50730f5605eff7ff6a12778161c8fd"
	
	
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
			F2 AA
		}
	
	condition:
		any of them
	
}
