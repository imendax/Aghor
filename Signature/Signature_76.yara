rule signature_76
{
	meta:
		author = "0xlsd"
		sample = "de0317f04b906c8dabf372dd8ae64dd2905a650ea69cade4fb32d1d3bee27119"
	
	
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
			31 B8 ?? ?? ?? ??
		}
	
	condition:
		any of them
	
}
