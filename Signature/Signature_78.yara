rule signature_78
{
	meta:
		author = "0xlsd"
		sample = "f2945c56e84346b1e251a57fc1b43c0ddfa77929f2deb8cbf0d460d532da5c2e"
	
	
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
			F7 B9 ?? ?? ?? ??
			B1 92
			B3 D8
			B1 92
		}
	
	condition:
		any of them
	
}
