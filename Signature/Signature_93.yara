rule signature_93
{
	meta:
		author = "0xlsd"
		sample = "0d837025d1d928ff795d560eb7b655603c60411142a1b6231bfe09f2ddde4d28"
	
	
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
			7F ??
			D7
			FA
			3B 69 ??
			A9 3B 69 B9 A9
		}
	
	condition:
		any of them
	
}
