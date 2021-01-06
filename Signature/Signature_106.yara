rule signature_106
{
	meta:
		author = "0xlsd"
		sample = "a4763fd2d0197646192d76abb47609d36e0da2b45c599b28fafbdda12e9ca2ed"
	
	
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
			37
			FB
			3A 05 ?? ?? ?? ??
			73 ??
			54
			56
		}
	
	condition:
		any of them
	
}
