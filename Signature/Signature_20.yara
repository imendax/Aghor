rule signature_20
{
	meta:
		author = "0xlsd"
		sample = "99a53e7896eee3417d02275b03ad0e25bc3530c2dee8968cc364f30e98e48fbc"
	
	
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
		}
	
	condition:
		any of them
	
}
