rule signature_21
{
	meta:
		author = "0xlsd"
		sample = "80005cdf0ccfe2648cd2b61f2197facd28b2cc015cf53fdbd77521602c73af29"
	
	
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
			CD 85
		}
	
	condition:
		any of them
	
}
