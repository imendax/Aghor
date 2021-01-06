rule signature_103
{
	meta:
		author = "0xlsd"
		sample = "b509519db91d64b86a2a0607fac9f56faeb030f5a2054e1006818da227441a78"
	
	
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
			46
			D6
			5A
			50
		}
	
	condition:
		any of them
	
}
