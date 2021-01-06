rule signature_122
{
	meta:
		author = "0xlsd"
		sample = "84a95c60954bcb072583b09293a99d93218dc981c2a3f5d78295b83c14473739"
	
	
	strings:
		$string_1 = {
			0F 03 0B
			01 06
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 E0
			11 00
			00 00
			10 00
			00 00
			20 00
			00 00
			00 40 ??
			00 10
			00 00
			00 02
		}
	
	condition:
		any of them
	
}
