rule signature_111
{
	meta:
		author = "0xlsd"
		sample = "df35e9e1d54768fd864ba8f9a74b0cacf9e1420845168cef71caae7ce677050c"
	
	
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
			50
			45
			00 00
			4C
			01 04 00
			9F
			94
		}
	
	condition:
		any of them
	
}
